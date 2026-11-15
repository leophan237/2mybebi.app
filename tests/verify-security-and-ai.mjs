import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const handler = require(path.join(ROOT, "api/ai.js"));
const html = readFileSync(path.join(ROOT, "2mybebi.html"), "utf8");
const vercelJson = JSON.parse(readFileSync(path.join(ROOT, "vercel.json"), "utf8"));

function createMockRes() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader(k, v) {
      this.headers[k.toLowerCase()] = v;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(obj) {
      this.body = obj;
      return this;
    },
    end(raw) {
      if (typeof raw === "string") {
        try { this.body = JSON.parse(raw); } catch { this.body = raw; }
      }
      return this;
    },
  };
}

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

console.log("\n[1/4] Kiểm thử Serverless Proxy /api/ai (OpenRouter · openai/gpt-6-luna)");

await test("Khóa cứng provider=openrouter và model=openai/gpt-6-luna", () => {
  assert.equal(handler._internals.LOCKED_PROVIDER, "openrouter");
  assert.equal(handler._internals.LOCKED_MODEL, "openai/gpt-6-luna");
});

await test("GET /api/ai trả về trạng thái cấu hình và header no-store, không lộ API key", async () => {
  const prevKey = process.env.OPENROUTER_API_KEY;
  const prevCode = process.env.APP_ACCESS_CODE;
  process.env.OPENROUTER_API_KEY = "sk-or-v1-secret-test-value-999999999";
  process.env.APP_ACCESS_CODE = "team-secret-pass";
  try {
    const res = createMockRes();
    await handler({ method: "GET", headers: { host: "2mybebi.vercel.app" }, socket: {} }, res);
    assert.equal(res.statusCode, 200);
    assert.ok(String(res.headers["cache-control"] || "").includes("no-store"));
    assert.deepEqual(res.body, {
      ok: true,
      configured: true,
      passcodeRequired: true,
      provider: "openrouter",
      model: "openai/gpt-6-luna",
    });
    assert.ok(!JSON.stringify(res.body).includes("sk-or-v1"), "Không được phép lộ API key");
  } finally {
    if (prevKey === undefined) delete process.env.OPENROUTER_API_KEY;
    else process.env.OPENROUTER_API_KEY = prevKey;
    if (prevCode === undefined) delete process.env.APP_ACCESS_CODE;
    else process.env.APP_ACCESS_CODE = prevCode;
  }
});

await test("Chặn Origin lạ và POST không có Origin (CSRF / proxy abuse)", async () => {
  const res = createMockRes();
  await handler({
    method: "POST",
    headers: { host: "2mybebi.vercel.app", origin: "https://evil-attacker.example" },
    body: { systemPrompt: "a", userPrompt: "b" },
    socket: {},
  }, res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.ok, false);

  const resNoOrigin = createMockRes();
  await handler({
    method: "POST",
    headers: { host: "2mybebi.vercel.app" },
    body: { systemPrompt: "a", userPrompt: "b" },
    socket: {},
  }, resNoOrigin);
  assert.equal(resNoOrigin.statusCode, 403);
});

await test("Kiểm tra timing-safe APP_ACCESS_CODE (thiếu/sai -> 401, đúng -> gọi OpenRouter)", async () => {
  const prevKey = process.env.OPENROUTER_API_KEY;
  const prevCode = process.env.APP_ACCESS_CODE;
  const origFetch = globalThis.fetch;
  process.env.OPENROUTER_API_KEY = "sk-or-v1-secret-test-value-888888888";
  process.env.APP_ACCESS_CODE = "passcode-2026";
  let capturedFetch = null;
  globalThis.fetch = async (url, init) => {
    capturedFetch = { url, init };
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          choices: [{ finish_reason: "stop", message: { content: '{"ok":true}' } }],
        };
      },
    };
  };
  try {
    const resMissing = createMockRes();
    await handler({
      method: "POST",
      headers: { host: "2mybebi.vercel.app", origin: "https://2mybebi.vercel.app", "x-forwarded-for": "10.0.0.1" },
      body: { action: "test", systemPrompt: "sys", userPrompt: "usr" },
      socket: {},
    }, resMissing);
    assert.equal(resMissing.statusCode, 401);
    assert.equal(resMissing.body.requiresPasscode, true);

    const resOk = createMockRes();
    await handler({
      method: "POST",
      headers: {
        host: "2mybebi.vercel.app",
        origin: "https://2mybebi.vercel.app",
        "x-app-passcode": "passcode-2026",
        "x-forwarded-for": "10.0.0.1",
      },
      body: {
        action: "chat",
        model: "attacker/other-model",
        systemPrompt: "sys",
        userPrompt: "usr",
        jsonMode: true,
      },
      socket: {},
    }, resOk);
    assert.equal(resOk.statusCode, 200);
    assert.equal(resOk.body.ok, true);
    assert.equal(resOk.body.model, "openai/gpt-6-luna");
    const sentPayload = JSON.parse(capturedFetch.init.body);
    assert.equal(sentPayload.model, "openai/gpt-6-luna", "Phải bỏ qua model client gửi và ép openai/gpt-6-luna");
    assert.equal(capturedFetch.url, "https://openrouter.ai/api/v1/chat/completions");
    assert.ok(capturedFetch.init.headers.Authorization.endsWith("sk-or-v1-secret-test-value-888888888"));
  } finally {
    globalThis.fetch = origFetch;
    if (prevKey === undefined) delete process.env.OPENROUTER_API_KEY;
    else process.env.OPENROUTER_API_KEY = prevKey;
    if (prevCode === undefined) delete process.env.APP_ACCESS_CODE;
    else process.env.APP_ACCESS_CODE = prevCode;
  }
});

await test("Xóa sạch bí mật (redactSecrets) khi upstream trả lỗi có dính key", async () => {
  const prevKey = process.env.OPENROUTER_API_KEY;
  const prevCode = process.env.APP_ACCESS_CODE;
  const origFetch = globalThis.fetch;
  delete process.env.APP_ACCESS_CODE;
  process.env.OPENROUTER_API_KEY = "sk-or-v1-supersecretleak1234567890";
  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    headers: new Map(),
    async text() {
      return 'Invalid auth sk-or-v1-supersecretleak1234567890 or AIzaSyDummySecretKey123456789012345';
    },
  });
  try {
    const res = createMockRes();
    await handler({
      method: "POST",
      headers: { host: "localhost:3000", origin: "http://localhost:3000", "x-forwarded-for": "10.0.0.2" },
      body: { systemPrompt: "sys", userPrompt: "usr" },
      socket: {},
    }, res);
    assert.equal(res.statusCode, 401);
    const serialized = JSON.stringify(res.body);
    assert.ok(!serialized.includes("supersecretleak"));
    assert.ok(!serialized.includes("AIzaSyDummy"));
    assert.ok(serialized.includes("[REDACTED"));
  } finally {
    globalThis.fetch = origFetch;
    if (prevKey === undefined) delete process.env.OPENROUTER_API_KEY;
    else process.env.OPENROUTER_API_KEY = prevKey;
    if (prevCode === undefined) delete process.env.APP_ACCESS_CODE;
    else process.env.APP_ACCESS_CODE = prevCode;
  }
});

await test("Rate limit chặn burst quá giới hạn và validate payload quá khổ", async () => {
  const ip = "198.51.100.77";
  for (let i = 0; i < 40; i++) {
    assert.equal(handler._internals.checkRateLimit(ip).allowed, true);
  }
  assert.equal(handler._internals.checkRateLimit(ip).allowed, false);

  assert.throws(
    () => handler._internals.validateAiRequestPayload({
      systemPrompt: "a",
      userPrompt: "x".repeat(160001),
    }),
    /vượt quá giới hạn/i
  );
});

console.log("\n[2/4] Kiểm thử cấu trúc HTML, CSP & Cú pháp JS trong 2mybebi.html");

await test("Không còn API key picker cũ, không còn document.write, giữ iframe YouTube ẩn chống lộ key", () => {
  assert.ok(!html.includes("w.document.write("), "Không được dùng document.write khi in");
  assert.ok(!html.includes("generativelanguage.googleapis.com"), "Không gọi trực tiếp Gemini API từ browser");
  assert.ok(!html.includes("api.anthropic.com"), "Không gọi trực tiếp Anthropic từ browser");
  assert.ok(!html.includes("api.openai.com"), "Không gọi trực tiếp OpenAI từ browser");
  assert.ok(html.includes('https://www.youtube.com/embed/-q1Jji6Dvw4?list=RD-q1Jji6Dvw4&start_radio=1&enablejsapi=1&playsinline=1&rel=0'));
  assert.ok(html.includes('Jay Chou Piano Playlist 04'), "Phải cập nhật tiêu đề/marquee bài hát mới");
  assert.ok(html.includes('id="mesh-backdrop"') || html.includes('class="mesh-backdrop"'));
  assert.ok(!/[\$]\(["']ai-(?:provider|model|api-key|custom-base-url|custom-model)["']\)/.test(html));
});

await test("Kiểm tra UI Trợ lý bài giảng: Pastel hồng chế độ 2, Chibi sticky 8 ảnh không quote, Equalizer + Marquee, Flower click", () => {
  assert.ok(html.includes('<meta name="referrer" content="strict-origin-when-cross-origin">'), "Phải có meta referrer để chống lỗi YouTube Error 153");
  assert.ok(html.includes("--paper:#fbf5ec") && html.includes("--accent:#b84a62") && html.includes("--earth-ochre:#c98a4b"), "Phải có palette Mệnh Thổ");
  assert.ok(html.includes("--accent:#c85a7c") && html.includes("--soft:#fdeef3"), "Chế độ Tóm tắt phải dùng bảng màu Pastel Hồng");
  assert.ok(!/\.mode-tab\[data-mode="summary"\]\.is-active\{[^}]*#485c7e/.test(html) && !/body\[data-mode="summary"\] \.primary\{[^}]*#485c7e/.test(html), "Gradient chế độ 2 không còn màu xanh xám đậm #485c7e");
  assert.ok(html.includes("ghibli-watercolor-svg"), "Phải có tranh màu nước Ghibli ở nền");
  assert.ok(!html.includes("mast-meta-tags") && !html.includes("Scrapbook Mệnh Thổ"), "Đã bỏ 2 nhãn ở header");
  assert.ok(!html.includes("reverie-meadow-card"), "Đã bỏ ô mô tả color palette");
  assert.ok(html.includes('<h1 id="hero-title">Trợ lý <em>bài giảng</em></h1>'), "Tiêu đề lớn là Trợ lý bài giảng");
  assert.ok(html.includes("Đa ngôn ngữ") && html.includes("Nhanh chóng") && html.includes("Dịch tự nhiên"), "Phải có đủ 3 keyword tính năng");
  assert.ok(html.includes('class="chill-audio-hidden" id="chill-player-wrap"') && !html.includes("chill-musicbox-btn"), "Ẩn hoàn toàn khung video YouTube và chỉ giữ nút Mute/Unmute");

  const leftRailRule = html.match(/\.left-rail\{[^}]*\}/);
  assert.ok(leftRailRule && leftRailRule[0].includes("position:sticky"), ".left-rail phải có position:sticky bám theo khi cuộn trang");
  assert.ok(html.includes("background-size:800% 100%") && html.includes('data-chibi="7"') && html.includes('data-dot="7"'), "Bộ Chibi phải đủ 8 ảnh (4 gốc + 4 mới)");
  assert.ok(!html.includes('class="comic-quote"') && !html.includes('class="comic-bubble"'), "Phải bỏ phần quote khỏi khung Chibi");

  assert.ok(!html.includes("Nhạc nền thư giãn") && !html.includes("Giai điệu Ghibli dịu nhẹ"), "Bỏ nhãn tĩnh Nhạc nền thư giãn / Giai điệu Ghibli dịu nhẹ");
  const eqMatch = html.match(/id="chill-eq"[^>]*>([\s\S]*?)<\/div>/);
  assert.ok(eqMatch && (eqMatch[1].match(/<span><\/span>/g) || []).length === 14, "#chill-eq phải có 14 cột equalizer kéo dài");
  assert.ok(html.includes("chillMarquee") && html.includes('class="chill-marquee-track" id="chill-sub-text"'), "Phải có chữ chạy cuộn từ phải qua trái tên bài hát");

  assert.ok(!html.includes('id="mesh-cursor-glow"') && html.includes("btn-flower-pop") && html.includes("click-flower-particle"), "Tắt hiệu ứng rê chuột trên nền và bật hiệu ứng nảy hoa khi click button");

  const stickerRuleMatch = html.match(/\.sticker-field\{[^}]*\}/);
  assert.ok(stickerRuleMatch && stickerRuleMatch[0].includes("position:relative"), ".sticker-field phải dùng position:relative");
  assert.ok(!/\.sticker-field\{[^}]*position:fixed/.test(html), "Không được dùng position:fixed trên .sticker-field gây che toolbox");

  const leftRailStart = html.indexOf('<div class="left-rail">');
  const chibiIdx = html.indexOf('id="chibi-showcase"');
  const chillCardIdx = html.indexOf('id="chill-card"');
  const chibiStageIdx = html.indexOf('id="chibi-stage"');
  const workbenchIdx = html.indexOf('<section class="workbench"');
  assert.ok(leftRailStart > 0 && chibiIdx > leftRailStart && chillCardIdx > chibiIdx && chibiStageIdx > chillCardIdx && workbenchIdx > chibiStageIdx, "Frame phát nhạc (#chill-card) và #chibi-stage phải nằm chung trong #chibi-showcase thuộc .left-rail trước .workbench");

  assert.ok(html.includes("family=Manrope:") && html.includes("Playfair+Display:"), "Phải nạp Google Fonts Manrope và Playfair Display");
  assert.ok(html.includes('--display:"Playfair Display"') && html.includes('--sans:"Manrope"'), "CSS variables phải dùng Playfair Display cho title và Manrope cho không chân");
  assert.ok(!html.includes('<header class="mast">'), "Đã bỏ header bar <header class=\"mast\">");
  const cornerCss = html.match(/\.api-corner-pill\{[^}]*\}/);
  assert.ok(cornerCss && cornerCss[0].includes("position:fixed") && cornerCss[0].includes("top:14px") && cornerCss[0].includes("right:18px"), ".api-corner-pill phải cố định gọn ở góc phải ngoài cùng");
  assert.ok(html.includes('class="api-corner-pill mast-note" id="mast-ai-pill"'), "#mast-ai-pill phải chuyển thành .api-corner-pill");

  const introEnd = html.indexOf("</aside>", leftRailStart);
  const introBlock = html.slice(leftRailStart, introEnd);
  assert.ok(introBlock.includes('<span class="brand">✿ 2mybebi<em>.</em></span>') && introBlock.includes('id="hero-title"'), "Thương hiệu 2mybebi phải nằm trong <aside class=\"intro\"> cùng tiêu đề Trợ lý bài giảng");
  const subtitleMatch = introBlock.match(/<p class="hero-subtitle">([\s\S]*?)<\/p>/);
  assert.ok(subtitleMatch && !/Trợ lý bài giảng/i.test(subtitleMatch[1]), "Mô tả .hero-subtitle liền kề không được lặp lại cụm Trợ lý bài giảng");

  assert.ok(!html.includes(".sticker-field::before") && !html.includes(".sticker-field::after") && !html.includes(".workbench::before"), "Đã bỏ họa tiết băng dính khỏi thẻ Chibi và Workbench");
  assert.ok(stickerRuleMatch && stickerRuleMatch[0].includes("background:transparent"), ".sticker-field phải bỏ nền card đặc");
  const workbenchCss = html.match(/\.workbench\{[^}]*\}/);
  assert.ok(workbenchCss && workbenchCss[0].includes("rgba(255,252,248,.46)"), ".workbench phải dùng nền kính trong suốt tinh tế");
});

await test("Kiểm tra vercel.json có CSP chặt và cấu hình /api/ai", () => {
  const rootHdrs = vercelJson.headers.find(h => h.source === "/(.*)")?.headers || [];
  const csp = rootHdrs.find(h => h.key === "Content-Security-Policy")?.value || "";
  assert.ok(csp.includes("frame-src https://www.youtube.com https://www.youtube-nocookie.com"));
  assert.ok(csp.includes("connect-src 'self' https://translate.googleapis.com"));
  assert.ok(!csp.includes("openrouter.ai"), "Browser không được kết nối trực tiếp tới openrouter.ai");
  assert.equal(vercelJson.functions?.["api/ai.js"]?.maxDuration, 60);
});

const scriptMatches = Array.from(html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)).map(m => m[1]);

await test("Toàn bộ các khối <script> inline biên dịch sạch bằng vm.Script", () => {
  assert.equal(scriptMatches.length, 3, "Kỳ vọng 3 khối <script> (JSZip + Engine + App controller)");
  for (let i = 0; i < scriptMatches.length; i++) {
    new vm.Script(scriptMatches[i], { filename: `2mybebi_script_${i}.js` });
  }
});

console.log("\n[3/4] Kiểm thử DocSecurity Runtime & Anti-Malware OpenXML (.pptx)");

// Tạo sandbox chạy JSZip (script 0) + DocSecurity (đầu script 1)
function extractDocSecurityAndZip() {
  const script1 = scriptMatches[1];
  const endMarker = "globalThis.SlideLingo = (() => {";
  const splitIdx = script1.indexOf(endMarker);
  assert.ok(splitIdx > 0, "Phải tìm thấy DocSecurity trước SlideLingo");
  const docSecSrc = script1.slice(0, splitIdx);

  const sandbox = {
    globalThis: null,
    self: null,
    window: undefined,
    TextDecoder,
    URL,
    Error,
    Set,
    Uint8Array,
    DataView,
    Array,
    String,
    Number,
    Boolean,
    Math,
    Object,
    setTimeout,
    clearTimeout,
    setImmediate,
  };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(scriptMatches[0], sandbox);
  vm.runInContext(docSecSrc, sandbox);
  assert.ok(sandbox.JSZip, "JSZip phải được nạp trong sandbox");
  assert.ok(sandbox.DocSecurity, "DocSecurity phải được nạp trong sandbox");
  return sandbox;
}

const secEnv = extractDocSecurityAndZip();
const { JSZip, DocSecurity } = secEnv;

async function buildSyntheticPptxBuffer(extraFiles = {}) {
  const zip = new JSZip();
  zip.file("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>');
  zip.file("ppt/presentation.xml", '<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst/></p:presentation>');
  zip.file("ppt/_rels/presentation.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>');
  for (const [k, v] of Object.entries(extraFiles)) {
    zip.file(k, v);
  }
  const u8 = await zip.generateAsync({ type: "uint8array" });
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

await test("DocSecurity.inspectZipDirectory chấp nhận PPTX sạch và chặn macro/ActiveX/OLE/Zip-Slip", async () => {
  const cleanBuf = await buildSyntheticPptxBuffer();
  const names = DocSecurity.inspectZipDirectory(cleanBuf, 60 * 1024 * 1024, ["ppt/presentation.xml", "[Content_Types].xml"]);
  assert.ok(names.has("ppt/presentation.xml"));

  const cleanWithChartBuf = await buildSyntheticPptxBuffer({
    "ppt/embeddings/Microsoft_Excel_Worksheet.xlsx": "safe-xlsx-bytes",
  });
  const chartNames = DocSecurity.inspectZipDirectory(cleanWithChartBuf, 60 * 1024 * 1024, ["ppt/presentation.xml", "[Content_Types].xml"]);
  assert.ok(chartNames.has("ppt/embeddings/Microsoft_Excel_Worksheet.xlsx"));

  for (const badPath of [
    "ppt/vbaProject.bin",
    "ppt/vbaData.xml",
    "_xmlsignatures/sig1.xml",
    "ppt/activeX/activeX1.xml",
    "ppt/embeddings/oleObject1.bin",
    "ppt/embeddings/macro.xlsm",
    "ppt/media/payload.exe",
  ]) {
    const poisoned = await buildSyntheticPptxBuffer({ [badPath]: "evil-bytes" });
    assert.throws(
      () => DocSecurity.inspectZipDirectory(poisoned, 60 * 1024 * 1024, ["ppt/presentation.xml", "[Content_Types].xml"]),
      /không an toàn|bị chặn|hợp lệ/i,
      `Phải chặn entry nguy hiểm: ${badPath}`
    );
  }
});

await test("DocSecurity.assertSafeXmlString chặn XXE <!DOCTYPE> & <!ENTITY>", () => {
  assert.throws(
    () => DocSecurity.assertSafeXmlString('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
    /không an toàn|DOCTYPE|ENTITY/i
  );
  assert.equal(
    DocSecurity.assertSafeXmlString('<p:sld xmlns:p="urn:p"/>'),
    '<p:sld xmlns:p="urn:p"/>'
  );
});

await test("DocSecurity.sanitizeExternalUrl giữ link https/http an toàn và chặn javascript:/vbscript:/file:/data:/UNC", () => {
  assert.equal(DocSecurity.sanitizeExternalUrl("https://2mybebi.app/lesson?id=1"), "https://2mybebi.app/lesson?id=1");
  assert.equal(DocSecurity.sanitizeExternalUrl("http://example.org/docs"), "http://example.org/docs");
  for (const bad of [
    "javascript:alert(1)",
    "  JaVaScRiPt:fetch('//evil')",
    "vbscript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "ms-msdt:/id PCWDiagnostic",
    "\\\\evil-server\\share\\x.dll",
    "ppaction://program",
  ]) {
    assert.equal(DocSecurity.sanitizeExternalUrl(bad), null, `Phải chặn URL nguy hiểm: ${bad}`);
  }
});

await test("DocSecurity.sanitizeRelsDocument giữ hyperlink https:// gốc và gỡ bỏ oleObject + javascript:", () => {
  const makeRel = (attrs) => ({
    localName: "Relationship",
    attrs: { ...attrs },
    parentNode: null,
    getAttribute(k) { return this.attrs[k] ?? null; },
    setAttribute(k, v) { this.attrs[k] = String(v); },
  });
  const doc = {
    documentElement: {
      children: [],
      removeChild(el) {
        const idx = this.children.indexOf(el);
        if (idx >= 0) this.children.splice(idx, 1);
      },
    },
  };
  const safeHyperlink = makeRel({
    Id: "rId1",
    Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
    Target: "https://2mybebi.app/docs",
    TargetMode: "External",
  });
  const badJsLink = makeRel({
    Id: "rId2",
    Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
    Target: "javascript:alert(document.cookie)",
    TargetMode: "External",
  });
  const badOle = makeRel({
    Id: "rId3",
    Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject",
    Target: "https://evil.example/payload.bin",
    TargetMode: "External",
  });
  for (const n of [safeHyperlink, badJsLink, badOle]) {
    n.parentNode = doc.documentElement;
    doc.documentElement.children.push(n);
  }
  const { removedIds, removedTargets } = DocSecurity.sanitizeRelsDocument(doc);
  assert.equal(doc.documentElement.children.length, 1);
  assert.equal(doc.documentElement.children[0].getAttribute("Target"), "https://2mybebi.app/docs");
  assert.ok(removedIds.has("rId2"));
  assert.ok(removedIds.has("rId3"));
  assert.equal(removedTargets.length, 2);
});

await test("DocSecurity.sanitizeSafeText lọc XSS/SVG, che bí mật và vô hiệu hóa Office DDE formula injection mà vẫn giữ bullet ESL", () => {
  const xss = 'Hello <script>alert(1)</script><svg onload="alert(2)"> world sk-or-v1-abc1234567890xyz';
  const cleanedXss = DocSecurity.sanitizeSafeText(xss, { formulaSafe: true });
  assert.ok(!cleanedXss.includes("<script"));
  assert.ok(!cleanedXss.includes("<svg"));
  assert.ok(!cleanedXss.includes("onload="));
  assert.ok(!cleanedXss.includes("abc1234567890xyz"));
  assert.ok(cleanedXss.includes("[REDACTED_SECRET]"));

  const formulas = [
    "=cmd|'/C calc'!A0",
    '=HYPERLINK("http://evil.example","Click")',
    "+cmd|'/C calc'!A0",
    "-cmd|'/C powershell'!A0",
    "@SUM(1+1)*cmd|'/C calc'!A0",
  ];
  for (const f of formulas) {
    const out = DocSecurity.sanitizeSafeText(f, { formulaSafe: true });
    assert.ok(out.startsWith("'"), `Công thức DDE phải được vô hiệu hóa bằng dấu nháy đơn: ${f} -> ${out}`);
  }

  // Đảm bảo câu ESL bình thường (gạch đầu dòng / SĐT) không bị hỏng
  assert.equal(DocSecurity.sanitizeSafeText("- Ask your partner politely.", { formulaSafe: true }), "- Ask your partner politely.");
  assert.equal(DocSecurity.sanitizeSafeText("+84 901 234 567", { formulaSafe: true }), "+84 901 234 567");
});

await test("Print HTML Vector chứa CSP strict chặn mọi script & remote img", () => {
  assert.ok(
    html.includes(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'none'; script-src 'none';">`),
    "buildPrintVectorHtml phải nhúng thẻ meta CSP strict"
  );
});

console.log("\n[4/4] Kiểm thử kết nối giữa UI Controller & AI Slide Batch");

await test("SlideLingo.convert nhận aiTranslateSlideBatch và UI form submit gọi /api/ai cho cả 2 chế độ", () => {
  assert.ok(html.includes("async function convert(buffer, target, translate, update = ()=>{}, options = {})"));
  assert.ok(html.includes("const aiBatchFn = typeof options?.aiTranslateSlideBatch === \"function\""));
  assert.ok(html.includes("{ aiTranslateSlideBatch }"));
  assert.ok(html.includes("if ($(\"ai-config-panel\")) $(\"ai-config-panel\").hidden = false;"));
});

console.log("\n[5/5] Kiểm thử SlideLingo OpenXML Triage, GPT-6 Luna Batch & Reflow Chống Tràn Thẻ / Đè Top Bar");

function createXmlDomEnv() {
  const decodeXml = s => String(s)
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
  const encodeXml = s => String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  class TextNode {
    constructor(data, ownerDocument) {
      this.nodeType = 3;
      this.data = String(data);
      this.parentNode = null;
      this.ownerDocument = ownerDocument;
    }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v ?? ""); }
    cloneNode() { return new TextNode(this.data, this.ownerDocument); }
  }

  class XmlElement {
    constructor(ns, tagName, ownerDocument) {
      this.nodeType = 1;
      this.namespaceURI = ns || null;
      this.tagName = tagName;
      this.nodeName = tagName;
      this.localName = tagName.includes(":") ? tagName.split(":")[1] : tagName;
      this.prefix = tagName.includes(":") ? tagName.split(":")[0] : null;
      this.ownerDocument = ownerDocument;
      this.parentNode = null;
      this.childNodes = [];
      this._attrs = [];
    }
    get children() { return this.childNodes.filter(c => c.nodeType === 1); }
    get firstElementChild() { return this.children[0] || null; }
    get attributes() { return this._attrs; }
    get firstChild() { return this.childNodes[0] || null; }
    get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
    get nextSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return idx >= 0 && idx + 1 < this.parentNode.childNodes.length ? this.parentNode.childNodes[idx + 1] : null;
    }
    get textContent() {
      return this.childNodes.map(c => c.textContent).join("");
    }
    set textContent(v) {
      this.childNodes = [];
      if (v !== "" && v != null) {
        const tn = new TextNode(String(v), this.ownerDocument);
        tn.parentNode = this;
        this.childNodes.push(tn);
      }
    }
    appendChild(node) {
      if (node.parentNode) node.parentNode.removeChild(node);
      node.parentNode = this;
      node.ownerDocument = this.ownerDocument;
      this.childNodes.push(node);
      return node;
    }
    insertBefore(newNode, refNode) {
      if (!refNode) return this.appendChild(newNode);
      if (newNode.parentNode) newNode.parentNode.removeChild(newNode);
      const idx = this.childNodes.indexOf(refNode);
      if (idx === -1) return this.appendChild(newNode);
      newNode.parentNode = this;
      newNode.ownerDocument = this.ownerDocument;
      this.childNodes.splice(idx, 0, newNode);
      return newNode;
    }
    removeChild(node) {
      const idx = this.childNodes.indexOf(node);
      if (idx >= 0) {
        this.childNodes.splice(idx, 1);
        node.parentNode = null;
      }
      return node;
    }
    getAttribute(name) {
      const a = this._attrs.find(x => x.name === name);
      return a ? a.value : null;
    }
    hasAttribute(name) {
      return this._attrs.some(x => x.name === name);
    }
    setAttribute(name, val) {
      const v = String(val);
      const a = this._attrs.find(x => x.name === name);
      if (a) a.value = v;
      else {
        const local = name.includes(":") ? name.split(":")[1] : name;
        this._attrs.push({ name, localName: local, ns: null, value: v });
      }
    }
    setAttributeNS(ns, qName, val) {
      const v = String(val);
      const local = qName.includes(":") ? qName.split(":")[1] : qName;
      const a = this._attrs.find(x => x.name === qName || (x.ns === ns && x.localName === local));
      if (a) a.value = v;
      else this._attrs.push({ name: qName, localName: local, ns, value: v });
    }
    getAttributeNS(ns, localName) {
      const a = this._attrs.find(x => (x.ns === ns && x.localName === localName) || (ns === "http://schemas.openxmlformats.org/officeDocument/2006/relationships" && x.name === "r:" + localName));
      return a ? a.value : null;
    }
    removeAttribute(name) {
      const idx = this._attrs.findIndex(x => x.name === name);
      if (idx >= 0) this._attrs.splice(idx, 1);
    }
    getElementsByTagNameNS(ns, local) {
      const out = [];
      const walk = el => {
        for (const c of el.children) {
          if ((ns === "*" || c.namespaceURI === ns) && (local === "*" || c.localName === local)) out.push(c);
          walk(c);
        }
      };
      walk(this);
      return out;
    }
    cloneNode(deep) {
      const copy = new XmlElement(this.namespaceURI, this.tagName, this.ownerDocument);
      copy._attrs = this._attrs.map(a => ({ ...a }));
      if (deep) {
        for (const c of this.childNodes) {
          const cc = c.cloneNode(true);
          cc.parentNode = copy;
          copy.childNodes.push(cc);
        }
      }
      return copy;
    }
  }

  class XmlDocument {
    constructor() {
      this.nodeType = 9;
      this.documentElement = null;
      this.ownerDocument = this;
    }
    createElementNS(ns, qName) {
      return new XmlElement(ns, qName, this);
    }
    getElementsByTagNameNS(ns, local) {
      const out = [];
      if (!this.documentElement) return out;
      if ((ns === "*" || this.documentElement.namespaceURI === ns) && (local === "*" || this.documentElement.localName === local)) {
        out.push(this.documentElement);
      }
      return out.concat(this.documentElement.getElementsByTagNameNS(ns, local));
    }
  }

  class DOMParser {
    parseFromString(xml) {
      const doc = new XmlDocument();
      const stack = [];
      const nsStack = [{ "": "" }];
      const tokenRe = /<\?[\s\S]*?\?>|<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([A-Za-z_][\w:.-]*)((?:\s+[A-Za-z_][\w:.-]*\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
      let m;
      while ((m = tokenRe.exec(xml))) {
        if (m[1] !== undefined) {
          if (stack.length) {
            const tn = new TextNode(m[1], doc);
            tn.parentNode = stack[stack.length - 1];
            stack[stack.length - 1].childNodes.push(tn);
          }
          continue;
        }
        if (m[6] !== undefined) {
          if (stack.length) {
            const txt = decodeXml(m[6]);
            const tn = new TextNode(txt, doc);
            tn.parentNode = stack[stack.length - 1];
            stack[stack.length - 1].childNodes.push(tn);
          }
          continue;
        }
        if (m[3] === undefined) continue;
        const closing = m[2] === "/";
        const qName = m[3];
        const attrRaw = m[4] || "";
        const selfClosing = m[5] === "/";
        if (closing) {
          stack.pop();
          nsStack.pop();
          continue;
        }
        const curNs = { ...nsStack[nsStack.length - 1] };
        const attrs = [];
        const attrRe = /([A-Za-z_][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
        let am;
        while ((am = attrRe.exec(attrRaw))) {
          const k = am[1];
          const v = decodeXml(am[2] !== undefined ? am[2] : am[3]);
          if (k === "xmlns") curNs[""] = v;
          else if (k.startsWith("xmlns:")) curNs[k.slice(6)] = v;
          attrs.push({ name: k, value: v });
        }
        const prefix = qName.includes(":") ? qName.split(":")[0] : "";
        const elNs = curNs[prefix] || null;
        const el = new XmlElement(elNs, qName, doc);
        for (const a of attrs) {
          const ap = a.name.includes(":") ? a.name.split(":")[0] : "";
          const local = a.name.includes(":") ? a.name.split(":")[1] : a.name;
          el._attrs.push({ name: a.name, localName: local, ns: ap ? (curNs[ap] || null) : null, value: a.value });
        }
        if (!doc.documentElement) doc.documentElement = el;
        else if (stack.length) el.parentNode = stack[stack.length - 1], stack[stack.length - 1].childNodes.push(el);
        if (!selfClosing) {
          stack.push(el);
          nsStack.push(curNs);
        }
      }
      return doc;
    }
  }

  class XMLSerializer {
    serializeToString(node) {
      if (!node) return "";
      if (node.nodeType === 9) return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + this.serializeToString(node.documentElement);
      if (node.nodeType === 3) return encodeXml(node.data);
      const attrs = node._attrs.map(a => ` ${a.name}="${encodeXml(a.value)}"`).join("");
      if (!node.childNodes.length) return `<${node.tagName}${attrs}/>`;
      return `<${node.tagName}${attrs}>${node.childNodes.map(c => this.serializeToString(c)).join("")}</${node.tagName}>`;
    }
  }

  const fakeDoc = {
    createElement(tag) {
      if (tag === "canvas") {
        return {
          width: 8,
          height: 8,
          getContext() {
            return {
              font: "16px sans-serif",
              measureText(t) {
                const fm = /([\d.]+)px/.exec(this.font);
                const sz = fm ? parseFloat(fm[1]) : 16;
                let w = 0;
                for (const ch of String(t || "")) {
                  w += /[\u3000-\uffef\u4e00-\u9faf]/.test(ch) ? sz * 1.0 : sz * 0.54;
                }
                return { width: w };
              },
              drawImage() {},
              getImageData() { return { data: new Uint8ClampedArray(16) }; },
            };
          },
        };
      }
      return {};
    },
  };

  const script1 = scriptMatches[1];
  const endMarker = "globalThis.LessonSummary = (() => {";
  const slSrc = script1.slice(0, script1.indexOf(endMarker));
  const sandbox = {
    globalThis: null, self: null, window: undefined,
    DOMParser, XMLSerializer, document: fakeDoc,
    TextDecoder, TextEncoder, URL, Error, Set, Map, WeakMap, ArrayBuffer, Uint8Array, Uint8ClampedArray, DataView,
    Array, String, Number, Boolean, Math, Object, RegExp, Date, JSON, Promise, console,
    setTimeout, clearTimeout, setImmediate,
  };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(scriptMatches[0], sandbox);
  vm.runInContext(slSrc, sandbox);
  return sandbox;
}

const slEnv = createXmlDomEnv();
const { SlideLingo } = slEnv;
const PT = SlideLingo._internals.PT;
const emu = pt => Math.round(pt * PT);

async function makeSingleSlidePptx(slideXml) {
  const z = new slEnv.JSZip();
  z.file("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>');
  z.file("ppt/presentation.xml", '<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/></p:presentation>');
  z.file("ppt/_rels/presentation.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/></Relationships>');
  z.file("ppt/slides/slide1.xml", slideXml);
  z.file("ppt/slides/_rels/slide1.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>');
  const u8 = await z.generateAsync({ type: "uint8array" });
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

await test("Slide 1 (Role-play CONVERSATION / PAIR WORK): dịch đủ tiêu đề + thẻ Student A/B và đẩy đường viền đáy không cắt ngang chữ", async () => {
  const s1Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:graphicFrame>
        <p:nvGraphicFramePr><p:cNvPr id="2" name="TopBar"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr>
        <p:xfrm><a:off x="0" y="0"/><a:ext cx="${emu(960)}" cy="${emu(30)}"/></p:xfrm>
        <a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table">
          <a:tbl><a:tblGrid><a:gridCol w="${emu(240)}"/><a:gridCol w="${emu(720)}"/></a:tblGrid>
            <a:tr h="${emu(30)}">
              <a:tc><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600"/><a:t>Unit 2</a:t></a:r></a:p></a:txBody></a:tc>
              <a:tc><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600"/><a:t>| Lesson 2 | Creative speaking practice</a:t></a:r></a:p></a:txBody></a:tc>
            </a:tr>
          </a:tbl>
        </a:graphicData></a:graphic>
      </p:graphicFrame>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="ConvTitle"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(96)}" y="${emu(36)}"/><a:ext cx="${emu(260)}" cy="${emu(28)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2000" b="1"/><a:t>CONVERSATION</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="PairWork"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(190)}" y="${emu(64)}"/><a:ext cx="${emu(220)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800" b="1"/><a:t>PAIR WORK</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="CardABg"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(36)}" y="${emu(220)}"/><a:ext cx="${emu(400)}" cy="${emu(210)}"/></a:xfrm><a:solidFill><a:srgbClr val="EDEDED"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"/><a:t>Student A</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="6" name="CardABody"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(44)}" y="${emu(248)}"/><a:ext cx="${emu(384)}" cy="${emu(176)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Your role is to suggest and ask questions to guide the planning.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Your plans are to:</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Ask about the immediate next steps.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Ask what this means for long-term collaboration.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:cxnSp>
        <p:nvCxnSpPr><p:cNvPr id="7" name="CardABorder"/><p:cNvCxnSpPr/><p:nvPr/></p:nvCxnSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(36)}" y="${emu(430)}"/><a:ext cx="${emu(400)}" cy="${emu(2)}"/></a:xfrm></p:spPr>
      </p:cxnSp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="8" name="KeyExprBtn"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(700)}" y="${emu(488)}"/><a:ext cx="${emu(140)}" cy="${emu(30)}"/></a:xfrm><a:solidFill><a:srgbClr val="6AA84F"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400" b="1"/><a:t>Key expressions</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const buf = await makeSingleSlidePptx(s1Xml);
  const aiCaptured = [];
  const out = await SlideLingo.convert(buf, "ja", async text => `[JA] ${text}`, () => {}, {
    aiTranslateSlideBatch: async ({ items }) => {
      aiCaptured.push(...items);
      const map = {};
      for (const it of items) {
        map[it.id] = { keepEnglish: false, mode: it.inCard ? "newline" : "inline", translation: `訳:${it.text.slice(0, 24)}` };
      }
      return map;
    },
  });
  assert.ok(out.bytes, "Slide 1 phải xuất ra PPTX đã dịch");
  assert.ok(aiCaptured.some(it => it.inCard === true && it.charBudget > 0 && it.boxWidthPt === 384), "GPT-6 Luna batch phải nhận inCard + boxWidthPt + charBudget của thẻ");

  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const resXml = await outZip.file("ppt/slides/slide1.xml").async("string");
  assert.ok(!resXml.includes("ユニット2"), "Top Bar table 'Unit 2' không được dịch");
  assert.ok(resXml.includes("会話"), "CONVERSATION phải được dịch");
  assert.ok(resXml.includes("ペアワーク"), "PAIR WORK phải được dịch");
  assert.ok(resXml.includes("計画："), "Your plans are to: phải được dịch");
  assert.ok(resXml.includes("重要表現"), "Key expressions phải được dịch");

  const resDoc = new slEnv.DOMParser().parseFromString(resXml, "application/xml");
  const sps = Array.from(resDoc.getElementsByTagNameNS("http://schemas.openxmlformats.org/presentationml/2006/main", "sp"));
  const bg = sps.find(s => s.getElementsByTagNameNS("http://schemas.openxmlformats.org/presentationml/2006/main", "cNvPr")[0]?.getAttribute("name") === "CardABg");
  const cxn = resDoc.getElementsByTagNameNS("http://schemas.openxmlformats.org/presentationml/2006/main", "cxnSp")[0];
  const bgOffY = Number(bg.getElementsByTagNameNS("http://schemas.openxmlformats.org/drawingml/2006/main", "off")[0].getAttribute("y"));
  const bgExtCy = Number(bg.getElementsByTagNameNS("http://schemas.openxmlformats.org/drawingml/2006/main", "ext")[0].getAttribute("cy"));
  const cxnY = Number(cxn.getElementsByTagNameNS("http://schemas.openxmlformats.org/drawingml/2006/main", "off")[0].getAttribute("y"));
  assert.ok(bgExtCy > emu(210), `Thẻ nền CardABg phải giãn cao hơn 210pt khi nội dung tăng: ${bgExtCy / PT}pt`);
  assert.ok(cxnY >= bgOffY + bgExtCy - emu(2), `Đường viền đáy CardABorder (${cxnY / PT}pt) phải trượt xuống đáy thẻ (${(bgOffY + bgExtCy) / PT}pt) thay vì cắt ngang chữ`);
});

await test("Slide 2 (Exercise 1 + Top Bar + Dialogues A/B): giữ nguyên Unit 2 & câu thoại/trắc nghiệm, đẩy Choose the best answer xuống dưới Top Bar", async () => {
  const s2Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:graphicFrame>
        <p:nvGraphicFramePr><p:cNvPr id="2" name="TopBar"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr>
        <p:xfrm><a:off x="0" y="0"/><a:ext cx="${emu(960)}" cy="${emu(46)}"/></p:xfrm>
        <a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table">
          <a:tbl><a:tblGrid><a:gridCol w="${emu(220)}"/><a:gridCol w="${emu(740)}"/></a:tblGrid>
            <a:tr h="${emu(46)}">
              <a:tc><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800"/><a:t>Unit 2</a:t></a:r></a:p></a:txBody></a:tc>
              <a:tc><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800"/><a:t>| Lesson 2 | Grammar recap | Exercise 1</a:t></a:r></a:p></a:txBody></a:tc>
            </a:tr>
          </a:tbl>
        </a:graphicData></a:graphic>
      </p:graphicFrame>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="PromptBox"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(80)}" y="${emu(50)}"/><a:ext cx="${emu(680)}" cy="${emu(34)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr anchor="ctr"/><a:p><a:r><a:rPr sz="1800" b="1"/><a:t>Choose the best answer to complete the sentences.</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="BubbleA"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(85)}" y="${emu(102)}"/><a:ext cx="${emu(460)}" cy="${emu(36)}"/></a:xfrm><a:solidFill><a:srgbClr val="FCE5CD"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600"/><a:t>A: Would you like to join us for dinner after the meeting?</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="BubbleB"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(180)}" y="${emu(148)}"/><a:ext cx="${emu(680)}" cy="${emu(64)}"/></a:xfrm><a:solidFill><a:srgbClr val="CFE2F3"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1600"/><a:t>B: That’s kind of you, but I 1______have an early night. I’m tired after the journey.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1600"/><a:t>a. will   b. could   c. am going to</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const buf = await makeSingleSlidePptx(s2Xml);
  const aiSent = [];
  const out = await SlideLingo.convert(buf, "ja", async text => `[JA] ${text}`, () => {}, {
    aiTranslateSlideBatch: async ({ items }) => {
      aiSent.push(...items);
      const map = {};
      for (const it of items) map[it.id] = { keepEnglish: false, mode: "newline", translation: "文を完成させる最適な答えを選びなさい。" };
      return map;
    },
  });
  assert.ok(out.bytes, "Slide 2 phải xuất ra PPTX đã dịch");
  assert.ok(!aiSent.some(it => /Would you like|1______|am going to/.test(it.text)), "Câu thoại A:/B:, chỗ trống 1______ và đáp án a/b/c phải được giữ 100% tiếng Anh ngay từ khâu triage");

  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const resXml = await outZip.file("ppt/slides/slide1.xml").async("string");
  assert.ok(!resXml.includes("ユニット2"), "Bảng Top Bar 'Unit 2' không được dịch sai thành ユニット2");
  assert.ok(resXml.includes("文を完成させる最適な答えを選びなさい。"), "PromptBox phải được dịch chuẩn xác");
  assert.ok(resXml.includes("A: Would you like to join us for dinner after the meeting?"));
  assert.ok(resXml.includes("a. will   b. could   c. am going to"));

  const resDoc = new slEnv.DOMParser().parseFromString(resXml, "application/xml");
  const sps = Array.from(resDoc.getElementsByTagNameNS("http://schemas.openxmlformats.org/presentationml/2006/main", "sp"));
  const promptSp = sps.find(s => s.getElementsByTagNameNS("http://schemas.openxmlformats.org/presentationml/2006/main", "cNvPr")[0]?.getAttribute("name") === "PromptBox");
  const promptY = Number(promptSp.getElementsByTagNameNS("http://schemas.openxmlformats.org/drawingml/2006/main", "off")[0].getAttribute("y"));
  assert.ok(promptY >= emu(48), `PromptBox (anchor="ctr", y=${promptY / PT}pt) phải nằm bên dưới Top Bar (46pt), tuyệt đối không đè ngược lên trên`);
});

async function makeMultiSlidePptx(slideXmls) {
  const z = new slEnv.JSZip();
  z.file("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>');
  const sldIds = slideXmls.map((_, i) => `<p:sldId id="${256 + i}" r:id="rId${i + 1}"/>`).join("");
  const rels = slideXmls.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide${i + 1}.xml"/>`).join("");
  z.file("ppt/presentation.xml", `<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldIdLst>${sldIds}</p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/></p:presentation>`);
  z.file("ppt/_rels/presentation.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels}</Relationships>`);
  slideXmls.forEach((xml, i) => {
    z.file(`ppt/slides/slide${i + 1}.xml`, xml);
    z.file(`ppt/slides/_rels/slide${i + 1}.xml.rels`, '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>');
  });
  const u8 = await z.generateAsync({ type: "uint8array" });
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

await test("Deck-Level Batching & Khử trùng lặp (5 slide): chỉ gọi AI 1 lần duy nhất, giữ keepEnglish không rơi xuống translateFn", async () => {
  const mkSlide = (idx, extraPrompt) => `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="SharedInst"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(50)}"/><a:ext cx="${emu(780)}" cy="${emu(40)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600"/><a:t>Work with your partner and compare answers.</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="SlideBadge_${idx}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(110)}"/><a:ext cx="${emu(500)}" cy="${emu(34)}"/></a:xfrm><a:solidFill><a:srgbClr val="E8EEF5"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1500"/><a:t>${extraPrompt}</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slides = [
    mkSlide(1, "Client Meeting Agenda"),
    mkSlide(2, "Quarterly Sales Review"),
    mkSlide(3, "Supplier Negotiation Tips"),
    mkSlide(4, "Project Milestone Signoff"),
    mkSlide(5, "Sample Email Phrase"),
  ];
  const buf = await makeMultiSlidePptx(slides);
  let aiCallCount = 0;
  let sentItems = [];
  let fallbackCalls = 0;

  const out = await SlideLingo.convert(
    buf,
    "vi",
    async text => { fallbackCalls++; return `[FB] ${text}`; },
    () => {},
    {
      aiTranslateSlideBatch: async ({ items }) => {
        aiCallCount++;
        sentItems = items;
        const map = {};
        for (const it of items) {
          if (it.text === "Sample Email Phrase") {
            map[it.id] = { keepEnglish: true, mode: "inline", translation: "" };
          } else {
            map[it.id] = { keepEnglish: false, mode: "inline", translation: `Dịch: ${it.text}` };
          }
        }
        return map;
      },
    }
  );

  assert.ok(out.bytes, "Deck 5 slide phải xuất ra PPTX hợp lệ");
  assert.equal(aiCallCount, 1, `Kỳ vọng gom toàn bộ 5 slide vào 1 lần gọi AI, thực tế: ${aiCallCount}`);
  const sharedMatches = sentItems.filter(it => it.text === "Work with your partner and compare answers.");
  assert.equal(sharedMatches.length, 1, "Câu lặp lại ở cả 5 slide phải được khử trùng lặp chỉ gửi 1 lần cho AI");
  assert.equal(fallbackCalls, 0, "Khi AI xử lý xong hoặc trả keepEnglish=true, tuyệt đối không gọi thêm translateFn dự phòng");
  assert.equal(out.report.aiUsedSlides, 5, "Cả 5 slide đều phải được áp dụng kết quả từ AI");
});

await test("Key expressions (3x2 Table + 6 overlaid phrase boxes): dịch tiêu đề ô bảng, auto-scale chống đè/tràn ô bảng & đổi màu bản dịch", async () => {
  const s3Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:graphicFrame>
        <p:nvGraphicFramePr><p:cNvPr id="2" name="TopBar"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr>
        <p:xfrm><a:off x="0" y="0"/><a:ext cx="${emu(960)}" cy="${emu(44)}"/></p:xfrm>
        <a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table">
          <a:tbl><a:tblGrid><a:gridCol w="${emu(220)}"/><a:gridCol w="${emu(740)}"/></a:tblGrid>
            <a:tr h="${emu(44)}">
              <a:tc><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600"/><a:t>Unit 2</a:t></a:r></a:p></a:txBody></a:tc>
              <a:tc><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600"/><a:t>| Lesson 2 | Business Communication | Key expressions</a:t></a:r></a:p></a:txBody></a:tc>
            </a:tr>
          </a:tbl>
        </a:graphicData></a:graphic>
      </p:graphicFrame>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="SubCyan"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(30)}" y="${emu(50)}"/><a:ext cx="${emu(560)}" cy="${emu(32)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800" b="1"><a:solidFill><a:srgbClr val="3AD0EC"/></a:solidFill></a:rPr><a:t>Key expressions: A phone call at work</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="DarkBtn"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(680)}" y="${emu(50)}"/><a:ext cx="${emu(160)}" cy="${emu(30)}"/></a:xfrm><a:solidFill><a:srgbClr val="1B365D"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400" b="1"><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill></a:rPr><a:t>Practice</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:graphicFrame>
        <p:nvGraphicFramePr><p:cNvPr id="5" name="ExprGrid"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr>
        <p:xfrm><a:off x="${emu(48)}" y="${emu(92)}"/><a:ext cx="${emu(864)}" cy="${emu(420)}"/></p:xfrm>
        <a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table">
          <a:tbl><a:tblGrid><a:gridCol w="${emu(432)}"/><a:gridCol w="${emu(432)}"/></a:tblGrid>
            <a:tr h="${emu(140)}">
              <a:tc><a:tcPr anchor="t"/><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"><a:solidFill><a:srgbClr val="1B365D"/></a:solidFill></a:rPr><a:t>Starting/Answering a call</a:t></a:r></a:p></a:txBody></a:tc>
              <a:tc><a:tcPr anchor="t"/><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"><a:solidFill><a:srgbClr val="1B365D"/></a:solidFill></a:rPr><a:t>Asking for someone</a:t></a:r></a:p></a:txBody></a:tc>
            </a:tr>
            <a:tr h="${emu(140)}">
              <a:tc><a:tcPr anchor="t"/><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"><a:solidFill><a:srgbClr val="1B365D"/></a:solidFill></a:rPr><a:t>Leaving a message</a:t></a:r></a:p></a:txBody></a:tc>
              <a:tc><a:tcPr anchor="t"/><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"><a:solidFill><a:srgbClr val="1B365D"/></a:solidFill></a:rPr><a:t>Taking a message</a:t></a:r></a:p></a:txBody></a:tc>
            </a:tr>
            <a:tr h="${emu(140)}">
              <a:tc><a:tcPr anchor="t"/><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"><a:solidFill><a:srgbClr val="1B365D"/></a:solidFill></a:rPr><a:t>Checking details</a:t></a:r></a:p></a:txBody></a:tc>
              <a:tc><a:tcPr anchor="t"/><a:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"><a:solidFill><a:srgbClr val="1B365D"/></a:solidFill></a:rPr><a:t>Ending a call</a:t></a:r></a:p></a:txBody></a:tc>
            </a:tr>
          </a:tbl>
        </a:graphicData></a:graphic>
      </p:graphicFrame>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="11" name="CellBoxR0C0"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(56)}" y="${emu(124)}"/><a:ext cx="${emu(416)}" cy="${emu(102)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr anchor="t"/>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Hello / Hi.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Good morning / afternoon.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ (Maria) speaking.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="12" name="CellBoxR0C1"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(488)}" y="${emu(120)}"/><a:ext cx="${emu(416)}" cy="${emu(110)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr anchor="ctr"/>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Can I speak to (Aitur Garitano), please?</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Is (Rosa) there?</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Is (Alek) in the office?</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Is that (Lukas)?</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Could I speak to ...?</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ I'd like to speak to ...</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Is ... there?</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="13" name="CellBoxR1C0"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(56)}" y="${emu(266)}"/><a:ext cx="${emu(416)}" cy="${emu(102)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr anchor="t"/>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Could I leave a message?</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ My number is...</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="14" name="CellBoxR1C1"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(488)}" y="${emu(266)}"/><a:ext cx="${emu(416)}" cy="${emu(102)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr anchor="t"/>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ I'm sorry, but she isn't here / available.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Can I take a message?</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="15" name="CellBoxR2C0"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(56)}" y="${emu(406)}"/><a:ext cx="${emu(416)}" cy="${emu(96)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr anchor="t"/>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ So, that's ...</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Is that right?</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="16" name="CellBoxR2C1"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(488)}" y="${emu(406)}"/><a:ext cx="${emu(416)}" cy="${emu(96)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr anchor="t"/>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ OK. Thanks.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>✓ Goodbye.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const buf = await makeSingleSlidePptx(s3Xml);
  const out = await SlideLingo.convert(buf, "vi", async text => `Dịch: ${text}`, () => {}, {
    aiTranslateSlideBatch: async ({ items }) => {
      const map = {};
      for (const it of items) {
        map[it.id] = { keepEnglish: false, mode: it.mode === "NEWLINE_AFTER" ? "newline" : "inline", translation: `VN:${it.text}` };
      }
      return map;
    },
  });
  assert.ok(out.bytes, "Slide Key expressions phải xuất ra PPTX hợp lệ");

  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const resXml = await outZip.file("ppt/slides/slide1.xml").async("string");
  assert.ok(resXml.includes("Mẫu câu trọng tâm: Gọi điện thoại nơi công sở"), "Tiêu đề Key expressions phải được dịch chuẩn");
  for (const hdr of ["Starting/Answering a call", "Asking for someone", "Leaving a message", "Taking a message", "Checking details", "Ending a call"]) {
    assert.ok(!resXml.includes(`VN:${hdr}`), `Tiêu đề nhóm "${hdr}" trong lưới Key expressions phải được lược bỏ (giữ nguyên tiếng Anh)`);
  }
  assert.ok(!resXml.includes("VN:Could I leave a message?"), "Các mẫu câu Key expressions phải được lược bỏ (giữ nguyên tiếng Anh)");
  assert.ok(!resXml.includes("VN:OK. Thanks."), "Các mẫu câu ending trong Key expressions phải được lược bỏ");
  assert.ok(!resXml.includes("B4235A") && !resXml.includes("FEF08A"), "Không còn sử dụng màu B4235A hoặc FEF08A");

  const resDoc = new slEnv.DOMParser().parseFromString(resXml, "application/xml");
  const P = "http://schemas.openxmlformats.org/presentationml/2006/main";
  const A = "http://schemas.openxmlformats.org/drawingml/2006/main";
  const sps = Array.from(resDoc.getElementsByTagNameNS(P, "sp"));
  const findSp = name => sps.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === name);

  const runColorOf = (sp, matchText) => {
    const runs = Array.from(sp.getElementsByTagNameNS(A, "r"));
    const targetRun = runs.find(r => (r.textContent || "").includes(matchText));
    return targetRun?.getElementsByTagNameNS(A, "srgbClr")[0]?.getAttribute("val");
  };
  assert.equal(runColorOf(findSp("SubCyan"), "Mẫu câu trọng tâm"), "000000", "Chữ gốc màu xanh lam sáng #3AD0EC trên nền sáng phải dùng bản dịch màu Đen 000000");
  assert.equal(runColorOf(findSp("DarkBtn"), "Luyện tập"), "FFFFFF", "Chữ gốc màu trắng #FFFFFF trên nền tối phải dùng bản dịch màu Trắng FFFFFF");
});

await test("Cobalt Blue (#1D4ED8) + normAutofit chống tràn thẻ hướng dẫn nhiều dòng (Instruction card)", async () => {
  const slideXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
      <p:pic>
        <p:nvPicPr><p:cNvPr id="9" name="CardBg"/><p:cNvPicPr/><p:nvPr/></p:nvPicPr>
        <p:blipFill><a:blip r:embed="rId2"/></p:blipFill>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(120)}"/><a:ext cx="${emu(416)}" cy="${emu(118)}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>
      </p:pic>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="10" name="InstrCard"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(64)}" y="${emu(124)}"/><a:ext cx="${emu(408)}" cy="${emu(110)}"/></a:xfrm><a:solidFill><a:srgbClr val="F8FAFC"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr anchor="t" wrap="square"/>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>Instruction:</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>Work in pairs to ask and answer the questions carefully.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>Read the company profile and take short notes about tasks.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>Check your partner's answers and switch roles together.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="000000"/></a:solidFill></a:rPr><a:t>Share your key findings with the whole class afterwards.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="11" name="LowerWall"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(252)}"/><a:ext cx="${emu(416)}" cy="${emu(60)}"/></a:xfrm><a:solidFill><a:srgbClr val="1E293B"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill></a:rPr><a:t>A: Next section sample text</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const buf = await makeSingleSlidePptx(slideXml);
  const out = await SlideLingo.convert(buf, "vi", async text => `VI:${text}`, () => {});
  assert.ok(out.bytes);
  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const resXml = await outZip.file("ppt/slides/slide1.xml").async("string");
  const P = "http://schemas.openxmlformats.org/presentationml/2006/main";
  const A = "http://schemas.openxmlformats.org/drawingml/2006/main";
  const doc = new slEnv.DOMParser().parseFromString(resXml, "application/xml");
  const card = Array.from(doc.getElementsByTagNameNS(P, "sp")).find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === "InstrCard");
  assert.ok(card);
  const viRun = Array.from(card.getElementsByTagNameNS(A, "r")).find(r => (r.textContent || "").includes("VI:Work in pairs"));
  assert.ok(viRun, "Thẻ hướng dẫn chữ đen phải được dịch");
  assert.equal(viRun.getElementsByTagNameNS(A, "srgbClr")[0]?.getAttribute("val"), "1D4ED8", "Chữ gốc đen #000000 trên nền sáng phải dùng bản dịch Xanh lam 1D4ED8");
  const cardY = Number(card.getElementsByTagNameNS(A, "off")[0].getAttribute("y")) / PT;
  const cardH = Number(card.getElementsByTagNameNS(A, "ext")[0].getAttribute("cy")) / PT;
  assert.ok(cardY + cardH <= 252, `InstrCard (bottom=${(cardY + cardH).toFixed(1)}pt) không được tràn qua mốc 252pt`);
  assert.ok(card.getElementsByTagNameNS(A, "normAutofit").length >= 1, "InstrCard phải được gắn <a:normAutofit/> chuẩn ECMA-376");
  const scaledSizes = Array.from(card.getElementsByTagNameNS(A, "rPr")).map(r => Number(r.getAttribute("sz"))).filter(Boolean);
  assert.ok(scaledSizes.some(sz => sz < 1400), `InstrCard phải tự co font size nhỏ hơn 14pt để vừa thẻ: [${scaledSizes.join(",")}]`);
});

await test("Extra questions True/False (5 pill-box <p:pic>) + CONVERSATION/PAIR WORK/Key expressions: dịch đủ, không tách khung & không đè Scenario", async () => {
  const PT = 12700;

  const slide1 = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree>
    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
    <p:sp><p:nvSpPr><p:cNvPr id="2" name="ConvLbl"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(95)}" y="${emu(40)}"/><a:ext cx="${emu(220)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
      <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800" b="1"/><a:t>CONVERSATION</a:t></a:r></a:p></p:txBody>
    </p:sp>
    <p:sp><p:nvSpPr><p:cNvPr id="3" name="PairLbl"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(105)}" y="${emu(72)}"/><a:ext cx="${emu(200)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
      <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800" b="1"/><a:t>PAIR WORK</a:t></a:r></a:p></p:txBody>
    </p:sp>
    <p:sp><p:nvSpPr><p:cNvPr id="4" name="ScenarioBox"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(106)}"/><a:ext cx="${emu(860)}" cy="${emu(75)}"/></a:xfrm><a:noFill/></p:spPr>
      <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400" b="1"/><a:t>Scenario: Enhancing team collaboration</a:t></a:r></a:p></p:txBody>
    </p:sp>
    <p:sp><p:nvSpPr><p:cNvPr id="5" name="KeyExprBtn"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(690)}" y="${emu(480)}"/><a:ext cx="${emu(140)}" cy="${emu(30)}"/></a:xfrm><a:solidFill><a:srgbClr val="65A30D"/></a:solidFill></p:spPr>
      <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1300" b="1"><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill></a:rPr><a:t>Key expressions</a:t></a:r></a:p></p:txBody>
    </p:sp>
  </p:spTree></p:cSld>
</p:sld>`;

  const tfStatements = [
    "Carmen is going to organize the next meeting to discuss the new hierarchy.",
    "The new hierarchy might not affect any employees.",
    "Carmen will inform Kirsten about any updates regarding the changes.",
    "The company is going to move to a new office before June ends.",
    "Kirsten should attend the next meeting because it will be about salaries.",
  ];
  const pillYs = [132, 212, 292, 372, 452];
  const pillXml = tfStatements.map((stmt, idx) => `
    <p:pic>
      <p:nvPicPr><p:cNvPr id="${20 + idx * 2}" name="PillPic${idx}"/><p:cNvPicPr/><p:nvPr/></p:nvPicPr>
      <p:blipFill><a:blip r:embed="rId2"/></p:blipFill>
      <p:spPr><a:xfrm><a:off x="${emu(120)}" y="${emu(pillYs[idx])}"/><a:ext cx="${emu(560)}" cy="${emu(40)}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>
    </p:pic>
    <p:sp>
      <p:nvSpPr><p:cNvPr id="${21 + idx * 2}" name="TfStmt${idx}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(128)}" y="${emu(pillYs[idx] + 4)}"/><a:ext cx="${emu(544)}" cy="${emu(32)}"/></a:xfrm><a:noFill/></p:spPr>
      <p:txBody><a:bodyPr wrap="square"/><a:p><a:r><a:rPr sz="1400"/><a:t>${stmt}</a:t></a:r></a:p></p:txBody>
    </p:sp>`).join("\n");

  const slide2 = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree>
    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
    <p:sp><p:nvSpPr><p:cNvPr id="2" name="InstrTF"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(46)}"/><a:ext cx="${emu(760)}" cy="${emu(36)}"/></a:xfrm><a:noFill/></p:spPr>
      <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"/><a:t>Read the email carefully and decide whether the following statements are True or False.</a:t></a:r></a:p></p:txBody>
    </p:sp>
    <p:sp><p:nvSpPr><p:cNvPr id="3" name="TFHdr"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(690)}" y="${emu(92)}"/><a:ext cx="${emu(180)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
      <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1500" b="1"/><a:t>True     False</a:t></a:r></a:p></p:txBody>
    </p:sp>
    ${pillXml}
    <p:sp><p:nvSpPr><p:cNvPr id="99" name="FooterBar"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="${emu(50)}" y="${emu(528)}"/><a:ext cx="${emu(910)}" cy="${emu(12)}"/></a:xfrm><a:solidFill><a:srgbClr val="1F2937"/></a:solidFill></p:spPr>
      <p:txBody><a:bodyPr/><a:p><a:endParaRPr/></p:txBody>
    </p:sp>
  </p:spTree></p:cSld>
</p:sld>`;

  const mockAiBatch = async (items) => {
    const map = {};
    for (const it of items) {
      // Mô phỏng AI gợi ý sai keepEnglish=true cho câu True/False và newline cho CONVERSATION/PAIR WORK
      const isTfStmt = /Carmen|hierarchy|company|Kirsten/i.test(it.text);
      map[it.id] = {
        keepEnglish: isTfStmt ? true : false,
        mode: /^(?:CONVERSATION|PAIR WORK|Key expressions|True\s+False)$/i.test(it.text) ? "newline" : "inline",
        translation: `VN:${it.text}`,
      };
    }
    return map;
  };

  const out1 = await SlideLingo.convert(await makeSingleSlidePptx(slide1), "vi", async text => `VN:${text}`, () => {}, {
    aiTranslateSlideBatch: mockAiBatch,
  });
  const out2 = await SlideLingo.convert(await makeSingleSlidePptx(slide2), "vi", async text => `VN:${text}`, () => {}, {
    aiTranslateSlideBatch: mockAiBatch,
  });

  const outZip1 = await JSZip.loadAsync(out1.bytes);
  const outZip2 = await JSZip.loadAsync(out2.bytes);
  const res1 = await outZip1.file("ppt/slides/slide1.xml").async("string");
  const res2 = await outZip2.file("ppt/slides/slide1.xml").async("string");

  const P = "http://schemas.openxmlformats.org/presentationml/2006/main";
  const A = "http://schemas.openxmlformats.org/drawingml/2006/main";
  const doc1 = new slEnv.DOMParser().parseFromString(res1, "application/xml");
  const sp1 = Array.from(doc1.getElementsByTagNameNS(P, "sp"));
  const textOfSp = name => sp1.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === name)?.textContent || "";
  const paraCountOfSp = name => sp1.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === name)?.getElementsByTagNameNS(A, "p").length || 0;
  assert.ok(/\(.+\)/.test(textOfSp("ConvLbl")) && paraCountOfSp("ConvLbl") === 1, `CONVERSATION phải dịch inline trong ngoặc: ${textOfSp("ConvLbl")}`);
  assert.ok(/\(.+\)/.test(textOfSp("PairLbl")) && paraCountOfSp("PairLbl") === 1, `PAIR WORK phải dịch inline trong ngoặc: ${textOfSp("PairLbl")}`);
  assert.ok(/\(.+\)/.test(textOfSp("KeyExprBtn")) && paraCountOfSp("KeyExprBtn") === 1, `Nút Key expressions phải được dịch inline trong ngoặc: ${textOfSp("KeyExprBtn")}`);
  const getRect = el => ({
    y: Number(el.getElementsByTagNameNS(A, "off")[0].getAttribute("y")) / PT,
    h: Number(el.getElementsByTagNameNS(A, "ext")[0].getAttribute("cy")) / PT,
  });
  const pairRect = getRect(sp1.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === "PairLbl"));
  const scenRect = getRect(sp1.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === "ScenarioBox"));
  assert.ok(pairRect.y + pairRect.h <= scenRect.y + 1, `PAIR WORK (bottom=${(pairRect.y + pairRect.h).toFixed(1)}) không được đè lên Scenario (top=${scenRect.y.toFixed(1)})`);

  // Kiểm tra 5 câu True/False ở Slide 2: tất cả phải được dịch & nằm lọt bên trong khung pill-box <p:pic>
  for (let idx = 0; idx < tfStatements.length; idx++) {
    assert.ok(res2.includes(`VN:${tfStatements[idx]}`), `Câu True/False #${idx + 1} bắt buộc phải được dịch`);
  }
  assert.ok(res2.includes("(VN:True     False)") || res2.includes("(VN:True False)"), "Nhãn True/False phải ghép inline cùng hàng");

  const doc2 = new slEnv.DOMParser().parseFromString(res2, "application/xml");
  const sp2 = Array.from(doc2.getElementsByTagNameNS(P, "sp"));
  const pic2 = Array.from(doc2.getElementsByTagNameNS(P, "pic"));
  for (let idx = 0; idx < tfStatements.length; idx++) {
    const picEl = pic2.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === `PillPic${idx}`);
    const spEl = sp2.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === `TfStmt${idx}`);
    const pr = getRect(picEl);
    const sr = getRect(spEl);
    assert.ok(sr.y >= pr.y - 1 && sr.y + sr.h <= pr.y + pr.h + 1,
      `TfStmt${idx} [${sr.y.toFixed(1)}..${(sr.y + sr.h).toFixed(1)}] phải nằm gọn trong PillPic${idx} [${pr.y.toFixed(1)}..${(pr.y + pr.h).toFixed(1)}], không tách khỏi khung hay đè footer`);
  }
});

await test("Kiểm thử đối chiếu bộ quy tắc 24 slide thực tế (BE1_Lesson 5) + chỉ 3 màu (000000/FFFFFF/1D4ED8) + File Queue & Mobile CSS", async () => {
  // 1. UI Queue & Mobile Responsive CSS checks on 2mybebi.html
  assert.ok(!/className\s*=\s*["']queue-btn-compress["']/.test(html), "Danh sách tệp không còn nút/nhãn Nén ngay");
  assert.ok(!/compBtn\.textContent\s*=\s*`⚡ Đã nén/.test(html), "Danh sách tệp không còn huy hiệu '⚡ Đã nén -XX%'");
  assert.match(html, /\.file-queue-state\{[^}]*white-space:\s*nowrap[^}]*flex-shrink:\s*0/, ".file-queue-state phải có white-space:nowrap và flex-shrink:0 để '✓ Hoàn tất' không bao giờ rớt thành 2 dòng");
  assert.match(html, /@media\(max-width:959px\)[\s\S]*\.left-rail\{display:contents\}/, "Mobile <=959px phải đặt .left-rail{display:contents} để đưa workbench lên trên");
  assert.match(html, /@media\(max-width:959px\)[\s\S]*\.api-corner-pill\{[^}]*position:static/, "Mobile <=959px phải bỏ position fixed/absolute của .api-corner-pill để không đè chữ");
  assert.match(html, /@media\(max-width:959px\)[\s\S]*overflow-x:clip/, "Mobile <=959px phải chặn tràn ngang overflow-x:clip");

  // 2. Real 24-slide BE1_Lesson 5 deck audit (if sample file exists on disk)
  const samplePath = "/Users/leo/Downloads/Thu\u0309y/BE1_Lesson 5_U2L2_60_Updated 12.08 - Co\u0301 logo.pptx";
  if (!existsSync(samplePath)) {
    console.log("  (Bỏ qua kiểm tra tệp mẫu cục bộ vì không có trên máy này)");
    return;
  }
  const u8 = readFileSync(samplePath);
  const origBytes = u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
  const A = "http://schemas.openxmlformats.org/drawingml/2006/main";
  const sl = SlideLingo;

  const translateJa = async text => `JA:${text}`;
  const out = await sl.convert(origBytes, "ja", translateJa, () => {});
  assert.ok(out.bytes, "Xuất PPTX 24 slide thành công");
  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const slideXml = async n => await outZip.file(`ppt/slides/slide${n}.xml`).async("string");

  // Slide 1 & 2: 1x1 banner table instructions MUST be translated
  const s1 = await slideXml(1);
  const s2 = await slideXml(2);
  assert.ok(s1.includes("JA:Listen to the audio"), "Slide 1 (bảng banner 1x1) phải được dịch");
  assert.ok(s2.includes("JA:Listen to phone calls"), "Slide 2 (bảng banner 1x1) phải được dịch");

  // Slide 3: skip Dicey Sentences / Column A / Column B; translate all 4 Instruction lines & preserve am/is/are + V-ing
  const s3 = await slideXml(3);
  assert.ok(!s3.includes("JA:Dicey Sentences"), "Slide 3: lược bỏ tiêu đề game 'Dicey Sentences'");
  assert.ok(!s3.includes("JA:Column A") && !s3.includes("JA:Column B"), "Slide 3: lược bỏ tiêu đề bảng Column A / Column B");
  assert.ok(s3.includes("JA:Instruction:"), "Slide 3: dòng Instruction phải được dịch");
  assert.ok(s3.includes("JA:Make a sentence using am/is/are + V-ing form."), "Slide 3: phải bảo toàn nguyên mẫu am/is/are + V-ing");

  // Slide 4: Cover -> single unified Lesson 2 translation, UNIT 2 paren, Objectives paren + 3 bullets
  const s4 = await slideXml(4);
  assert.ok(s4.includes("第2課：文法とビジネスコミュニケーション"), "Slide 4 Cover: gộp khối tiêu đề Lesson 2 thành 1 bản dịch");
  assert.ok(s4.includes("(会社)"), "Slide 4 Cover: UNIT 2: COMPANY phải chèn (会社)");
  assert.ok(s4.includes("(学習目標)"), "Slide 4 Cover: Objectives phải chèn (学習目標)");

  // Slides 5, 10, 14, 18 (Section Dividers): translated & Slide 18 NOTE skipped
  const s14 = await slideXml(14);
  const s18 = await slideXml(18);
  assert.ok(s14.includes("会話アクティビティ"), "Slide 14 Divider 'Conversation activator' phải được dịch");
  assert.ok(s18.includes("追加練習") && !s18.includes("JA:NOTE:") && !s18.includes("JA:These slides"), "Slide 18: dịch EXTRA PRACTICE nhưng lược bỏ NOTE: These slides...");

  // Slide 6 & 7: Grammar Form
  const s6 = await slideXml(6);
  const s7 = await slideXml(7);
  assert.ok(s6.includes("(分類)") && s6.includes("(肯定文)") && !s6.includes("JA:I am working"), "Slide 6: chỉ dịch hàng/cột tiêu đề bảng ngữ pháp");
  assert.ok(s7.includes("(肯定文)") && s7.includes("(否定文)"), "Slide 7: dịch Positive / Negative trong thanh tiêu đề bảng");

  // Slide 9: Cyan heading + Dark-blue theory ("We use...", "It gives...") + Formula & Examples labels; skip 🔹 examples
  const s9 = await slideXml(9);
  assert.ok(s9.includes("JA:Using 「Always」 in Present Continuous for Annoyance"), "Slide 9: dịch tiêu đề cyan & giữ 「Always」");
  assert.ok(s9.includes("(公式)") && s9.includes("(例文)"), "Slide 9: dịch Formula (公式) & Examples (例文)");
  assert.ok(s9.includes("JA:We use") && s9.includes("JA:It gives"), "Slide 9: dịch nội dung giải thích ngữ pháp 'We use...' và 'It gives...'");
  assert.ok(!s9.includes("JA:🔹"), "Slide 9: lược bỏ các câu ví dụ có biểu tượng 🔹");

  // Slides 11, 12, 13, 16: Pruned grids/chips/phrases/forms matching real slide order
  const s11 = await slideXml(11);
  const s12 = await slideXml(12);
  const s13 = await slideXml(13);
  const s16 = await slideXml(16);
  assert.ok(!s11.includes("JA:Thanks") && !s11.includes("ありがとうございました"), "Slide 11: lược bỏ word-bank chip 'Thanks'");
  assert.ok(s12.includes("JA:Look at the dialogue again") && !s12.includes("JA:Starting/Answering") && !s12.includes("JA:Teresa Baum"), "Slide 12: dịch hướng dẫn Exercise 2 nhưng lược bỏ 6 tiêu đề cột & thẻ hội thoại");
  assert.ok(s13.includes("基本表現：職場での電話"), "Slide 13: dịch tiêu đề Key expressions: A phone call at work");
  assert.ok(!s13.includes("Starting/Answering a call (") && !s13.includes("JA:Starting/Answering"), "Slide 13: lược bỏ 6 tiêu đề cột 3x2");
  assert.ok(!s13.includes("JA:Hello") && !s13.includes("JA:✓"), "Slide 13: lược bỏ toàn bộ cụm Key expressions");
  assert.ok(s16.includes("JA:Make a dialogue") && !s16.includes("JA:Message for") && !s16.includes("JA:Call back"), "Slide 16: dịch hướng dẫn nhưng lược bỏ nhãn form Message / Call back? Urgent?");

  // Slide 17: Did you know ? + all 3 body paragraphs incl. trailing 📞
  const s17 = await slideXml(17);
  assert.ok(s17.includes("(ご存知ですか？)"), "Slide 17: dịch 'Did you know ?'");
  assert.ok(s17.includes("JA:") && s17.includes("leaving a message!"), "Slide 17: giữ & dịch đủ 3 đoạn kể cả đoạn kết thúc bằng 📞");

  // Slide 19: Only top title & instruction, SKIP 6 matching cards
  const s19 = await slideXml(19);
  assert.ok(s19.includes("現在進行形の用法") && s19.includes("JA:Read and match"), "Slide 19: dịch tiêu đề + hướng dẫn");
  assert.ok(!s19.includes("JA:To describe") && !s19.includes("JA:The company is doing"), "Slide 19: lược bỏ toàn bộ 6 thẻ ghép đôi");

  // Slide 20: Making a survey! + all 4 lines
  const s20 = await slideXml(20);
  assert.ok(s20.includes("(アンケート調査をしましょう！)") && s20.includes("JA:Work in pairs"), "Slide 20: dịch 'Making a survey!' & các dòng hướng dẫn");

  // Slide 22 (Wrap-up) được dịch; Slide 24 THANKS thuần cảm ơn vẫn được bỏ qua
  const s22 = await slideXml(22);
  assert.ok(s22.includes("まとめ") || s22.includes("JA:"), "Slide 22: dịch nội dung Wrap-up / Review");
  const s24 = await slideXml(24);
  assert.ok(!s24.includes('descr="sl:ja"') && !s24.includes("JA:") && !s24.includes("ありがとうございました"), "Slide 24: bỏ qua slide thuần Thank you");
  const hasEmptyWarn24 = out.report.warnings.some(w => w.number === 24 && w.text.includes("Chưa nhận diện"));
  assert.ok(!hasEmptyWarn24, "Slide 24: không phát sinh cảnh báo");

  // Strict 3-color audit across ALL translated runs in ALL 24 slides
  const ALLOWED_COLORS = new Set(["000000", "FFFFFF", "1D4ED8"]);
  const badColors = [];
  for (let n = 1; n <= 24; n++) {
    const doc = new slEnv.DOMParser().parseFromString(await slideXml(n), "application/xml");
    const runs = Array.from(doc.getElementsByTagNameNS(A, "r"));
    for (const r of runs) {
      const rPr = r.getElementsByTagNameNS(A, "rPr")[0];
      if (!rPr || rPr.getAttribute("lang") !== "ja-JP") continue;
      // Only check newly injected bilingual runs (they carry our target accent srgbClr + Yu Gothic)
      const ea = rPr.getElementsByTagNameNS(A, "ea")[0]?.getAttribute("typeface");
      if (ea !== "Yu Gothic") continue;
      const val = rPr.getElementsByTagNameNS(A, "srgbClr")[0]?.getAttribute("val");
      if (!ALLOWED_COLORS.has(val)) {
        badColors.push(`Slide ${n} "${r.textContent.trim().slice(0, 40)}" -> ${val}`);
      }
    }
  }
  assert.deepEqual(badColors, [], `Mọi chữ dịch phải strictly dùng 000000 / FFFFFF / 1D4ED8, phát hiện màu lạ: ${badColors.join("; ")}`);

  // Verify Section Dividers (Slide 5, 10, 14, 18) & Slide 4 cover got FFFFFF White
  for (const n of [4, 5, 10, 14, 18]) {
    const doc = new slEnv.DOMParser().parseFromString(await slideXml(n), "application/xml");
    const trColors = Array.from(doc.getElementsByTagNameNS(A, "r"))
      .filter(r => r.getElementsByTagNameNS(A, "rPr")[0]?.getAttribute("lang") === "ja-JP" && r.getElementsByTagNameNS(A, "ea")[0]?.getAttribute("typeface") === "Yu Gothic")
      .map(r => r.getElementsByTagNameNS(A, "srgbClr")[0]?.getAttribute("val"));
    assert.ok(trColors.length > 0 && trColors.every(c => c === "FFFFFF"), `Slide ${n} (nền tối/divider) phải dùng chữ dịch Trắng FFFFFF, thực tế: [${trColors.join(",")}]`);
  }
});

await test("Slide 9 (Giải thích ngữ pháp + Xóa dòng rỗng + Anti-Overlap): dịch cả tiêu đề Cyan và lý thuyết xanh đậm, đẩy Examples không chồng chéo", async () => {
  const s9Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="CyanTitle"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(20)}" y="${emu(18)}"/><a:ext cx="${emu(720)}" cy="${emu(34)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2200" b="1"><a:solidFill><a:srgbClr val="00C8FF"/></a:solidFill></a:rPr><a:t>Using &quot;Always&quot; in Present Continuous for Annoyance</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="TheoryBox"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(20)}" y="${emu(62)}"/><a:ext cx="${emu(900)}" cy="${emu(112)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1800"><a:solidFill><a:srgbClr val="1B4965"/></a:solidFill></a:rPr><a:t>We use &quot;always&quot; + present continuous to talk about actions that happen too often and can be annoying.</a:t></a:r></a:p>
          <a:p><a:endParaRPr sz="1800"/></a:p>
          <a:p><a:r><a:rPr sz="1800"><a:solidFill><a:srgbClr val="1B4965"/></a:solidFill></a:rPr><a:t>It gives the idea of complaining or frustration.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="ExamplesBox"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(160)}" y="${emu(180)}"/><a:ext cx="${emu(680)}" cy="${emu(190)}"/></a:xfrm><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1800" b="1"/><a:t>💡 Formula: Subject + am/ is/ are + always + V-ing + object.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1600" b="1"/><a:t>Examples:</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1500"/><a:t>🔹 She is always coming late to meetings.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1500"/><a:t>🔹 Why are you always complaining about the schedule?</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const out = await SlideLingo.convert(await makeSingleSlidePptx(s9Xml), "vi", async text => `VN:${text}`);
  assert.equal(out.report.notes, 0, "100% bản dịch phải ở trên mặt slide (notes=0)");
  const logs = SlideLingo.lastLayoutLog || [];
  assert.ok(logs.length === 1 && logs[0].collisions.length === 0, `Slide 9 không được còn va chạm: ${JSON.stringify(logs)}`);

  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const resXml = await outZip.file("ppt/slides/slide1.xml").async("string");
  const P = "http://schemas.openxmlformats.org/presentationml/2006/main";
  const A = "http://schemas.openxmlformats.org/drawingml/2006/main";
  const doc = new slEnv.DOMParser().parseFromString(resXml, "application/xml");
  const sps = Array.from(doc.getElementsByTagNameNS(P, "sp"));
  const getBox = name => {
    const el = sps.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === name);
    return {
      el,
      text: el?.textContent || "",
      y: Number(el.getElementsByTagNameNS(A, "off")[0].getAttribute("y")) / PT,
      h: Number(el.getElementsByTagNameNS(A, "ext")[0].getAttribute("cy")) / PT,
    };
  };
  const cyanBox = getBox("CyanTitle");
  const theory = getBox("TheoryBox");
  const examples = getBox("ExamplesBox");
  assert.ok(cyanBox.text.includes('VN:Using "Always" in Present Continuous for Annoyance'), `Phải dịch tiêu đề Cyan, thực tế: ${cyanBox.text}`);
  assert.ok(theory.text.includes("VN:We use") && theory.text.includes('"always"'), `Phải dịch câu giải thích 'We use...' và giữ từ khóa "always", thực tế: ${theory.text}`);
  assert.ok(theory.text.includes("VN:It gives the idea of complaining or frustration."), `Phải dịch câu giải thích 'It gives...', thực tế: ${theory.text}`);
  assert.ok(examples.text.includes("(Công thức)") && examples.text.includes("(Ví dụ)"), `Phải dịch nhãn Formula & Examples, thực tế: ${examples.text}`);
  assert.ok(!examples.text.includes("VN:🔹"), `Phải giữ nguyên các câu ví dụ có 🔹, thực tế: ${examples.text}`);
  assert.ok(theory.y + theory.h <= examples.y + 1, `TheoryBox (${(theory.y + theory.h).toFixed(1)}) không được đè lên ExamplesBox (${examples.y.toFixed(1)})`);
  const emptyParas = Array.from(theory.el.getElementsByTagNameNS(A, "p")).filter(p => !p.textContent.trim());
  assert.equal(emptyParas.length, 0, "Đoạn <a:p> rỗng xen giữa phải được gộp gọn bằng spcBef");
  const theoryTrColors = Array.from(theory.el.getElementsByTagNameNS(A, "r"))
    .filter(r => r.getElementsByTagNameNS(A, "rPr")[0]?.getAttribute("lang") === "vi-VN")
    .map(r => r.getElementsByTagNameNS(A, "srgbClr")[0]?.getAttribute("val"));
  assert.ok(theoryTrColors.length > 0 && theoryTrColors.every(c => c === "000000"), `Chữ dịch cho chữ gốc xanh đậm #1B4965 phải là Đen 000000, thực tế: [${theoryTrColors.join(",")}]`);
});

await test("Nhóm 5 (Review / Note / Tip / Wrap-up) + Guards (Slide 19 Read & match + Pure Thanks)", async () => {
  const slideReview = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="WrapTitle"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(25)}"/><a:ext cx="${emu(300)}" cy="${emu(34)}"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2400" b="1"/><a:t>Wrap-up</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="ReviewList"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(75)}"/><a:ext cx="${emu(840)}" cy="${emu(260)}"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1600"/><a:t>In today's lesson, we learned how to use present continuous for annoyance.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1600"/><a:t>Note: Put always between be and the -ing verb.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1600"/><a:t>Tip: Sound polite when complaining to colleagues.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1600"/><a:t>Remember: Check subject-verb agreement before speaking.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1200"/><a:t>NOTE: These slides are for internal teacher use only.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slideMatch = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="MatchTitle"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(25)}"/><a:ext cx="${emu(500)}" cy="${emu(34)}"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2400" b="1"/><a:t>Use of Present Continuous Tense</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="MatchDir"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(70)}"/><a:ext cx="${emu(400)}" cy="${emu(28)}"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600"/><a:t>Read and match.</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="MatchCard1"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(120)}"/><a:ext cx="${emu(380)}" cy="${emu(60)}"/></a:xfrm><a:solidFill><a:srgbClr val="E2E8F0"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1500"/><a:t>To describe activities happening at the moment of speaking</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="MatchCard2"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(460)}" y="${emu(120)}"/><a:ext cx="${emu(380)}" cy="${emu(60)}"/></a:xfrm><a:solidFill><a:srgbClr val="E2E8F0"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1500"/><a:t>The company is doing well this year.</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slideThanks = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="Thanks"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(200)}" y="${emu(200)}"/><a:ext cx="${emu(500)}" cy="${emu(60)}"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="3600" b="1"/><a:t>Thank you!</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="QA"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(200)}" y="${emu(270)}"/><a:ext cx="${emu(500)}" cy="${emu(40)}"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2000"/><a:t>Do you have any questions?</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const buf = await makeMultiSlidePptx([slideReview, slideMatch, slideThanks]);

  const out = await SlideLingo.convert(buf, "vi", async text => `VN:${text}`);
  assert.equal(out.report.notes, 0, "Không được đẩy bản dịch sang Speaker Notes");
  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const s1 = await outZip.file("ppt/slides/slide1.xml").async("string");
  const s2 = await outZip.file("ppt/slides/slide2.xml").async("string");
  const s3 = await outZip.file("ppt/slides/slide3.xml").async("string");

  assert.ok(s1.includes("Tổng kết"), "Slide Review phải dịch tiêu đề Wrap-up");
  assert.ok(s1.includes("VN:In today's lesson"), "Phải dịch câu tổng kết In today's lesson...");
  assert.ok(s1.includes("VN:Note: Put always"), "Phải dịch Note: dành cho học viên");
  assert.ok(s1.includes("VN:Tip: Sound polite"), "Phải dịch Tip:");
  assert.ok(s1.includes("VN:Remember: Check"), "Phải dịch Remember:");
  assert.ok(!s1.includes("VN:NOTE: These slides"), "Giữ nguyên ghi chú nội bộ của giáo viên NOTE: These slides...");

  assert.ok(s2.includes("Cách dùng thì hiện tại tiếp diễn") && s2.includes("VN:Read and match."), "Slide Match phải dịch tiêu đề & đề bài Read and match");
  assert.ok(!s2.includes("VN:To describe") && !s2.includes("VN:The company is doing"), "Không được dịch các thẻ ghép đôi (Slide 19)");

  assert.ok(!s3.includes("VN:") && !out.report.warnings.some(w => w.number === 3), "Slide thuần Thank you! phải được bỏ qua và không phát sinh cảnh báo");
});

await test("Anti-Overlap Stress Test (CONVERSATION + PAIR WORK + Scenario hơi chồng mép & nhiều thẻ dày đặc): collisions = 0 & notes = 0", async () => {
  const denseXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="ConvTitle"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(22)}"/><a:ext cx="${emu(260)}" cy="${emu(30)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2000" b="1"/><a:t>CONVERSATION</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="PairSub"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(48)}"/><a:ext cx="${emu(220)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800" b="1"/><a:t>PAIR WORK</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="ScenarioCard"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(72)}"/><a:ext cx="${emu(880)}" cy="${emu(96)}"/></a:xfrm><a:solidFill><a:srgbClr val="F8FAFC"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1500" b="1"/><a:t>Scenario: Enhancing cross-team collaboration after a company reorganization</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Situation: Two project teams are struggling to communicate clearly during weekly status updates and missed key deadlines.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="StudentACard"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(174)}"/><a:ext cx="${emu(420)}" cy="${emu(220)}"/></a:xfrm><a:solidFill><a:srgbClr val="E2E8F0"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1600" b="1"/><a:t>Student A</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Your role is to suggest practical solutions and ask follow-up questions about timeline commitments.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Your plans are to:</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Propose a weekly joint standup meeting every Monday morning.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Ask what tools would make shared progress tracking much clearer.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="6" name="StudentBCard"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(500)}" y="${emu(174)}"/><a:ext cx="${emu(420)}" cy="${emu(220)}"/></a:xfrm><a:solidFill><a:srgbClr val="DBEAFE"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1600" b="1"/><a:t>Student B</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Your role is to describe concrete actions your team can deliver right away.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Your plans are to:</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>Share the updated roadmap and assign a single coordinator per milestone.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="7" name="BottomTip"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(415)}"/><a:ext cx="${emu(880)}" cy="${emu(68)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"/><a:t>Present your agreed action plan to the class after finishing the role-play practice.</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const out = await SlideLingo.convert(
    await makeSingleSlidePptx(denseXml),
    "ja",
    async text => `JA:${text}（詳細で丁寧なビジネス表現の日本語翻訳テキストを追加確認します）`
  );
  assert.equal(out.report.notes, 0, "Tuyệt đối không được đẩy bản dịch xuống Speaker Notes khi slide chật");
  const logs = SlideLingo.lastLayoutLog || [];
  assert.equal(logs.length, 1);
  assert.equal(logs[0].collisions.length, 0, `Không được còn bất kỳ va chạm nào trên slide dày đặc: ${JSON.stringify(logs[0].collisions)}`);

  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const resXml = await outZip.file("ppt/slides/slide1.xml").async("string");
  assert.ok(resXml.includes("会話") && resXml.includes("ペアワーク") && resXml.includes("JA:Scenario:") && resXml.includes("学生A"), "Đủ bản dịch cho tiêu đề và thẻ vai trò");
});

await test("Giới hạn dung lượng tệp tải lên tối đa 600 MB cho cả DocSecurity, Tool 1 (SlideLingo), Tool 2 (LessonSummary) & bộ nén PPTX", async () => {
  const expected600Mb = 600 * 1024 * 1024;
  assert.equal(SlideLingo.MAX_FILE, expected600Mb, "SlideLingo.MAX_FILE phải bằng 600 MB");
  assert.match(html, /const MAX_ENTRY_BYTES = 600 \* 1024 \* 1024;/, "DocSecurity.MAX_ENTRY_BYTES phải đạt 600 MB");
  assert.match(html, /const MAX_TOTAL_BYTES = 1800 \* 1024 \* 1024;/, "DocSecurity.MAX_TOTAL_BYTES phải đạt 1800 MB");
  assert.match(html, /function inspectZipDirectory\(buffer, maxFileBytes = 600 \* 1024 \* 1024/, "inspectZipDirectory mặc định 600 MB");
  assert.match(html, /const MAX_FILE = 600 \* 1024 \* 1024;/, "LessonSummary.MAX_FILE phải bằng 600 MB");
  assert.match(html, /inspectZipDirectory\(rawBuf, 600 \* 1024 \* 1024/, "compressPptxFile phải cho phép tối đa 600 MB");
  assert.ok(html.includes("tối đa 600 MB mỗi tệp") && html.includes("hoặc quá 600 MB"), "Thông báo UI phải hiển thị mức 600 MB");
  assert.ok(!/\b60\s*MB\b/.test(html), "Không được còn sót chuỗi giới hạn cũ 60 MB trong 2mybebi.html");
});

await test("Hồi quy U5L3: section divider 01–09 & defRPr, sysClr lastClr, lumMod/lumOff card, Track prefix, guard đáp án ____ & chống crash widenBounds", async () => {
  const P = "http://schemas.openxmlformats.org/presentationml/2006/main";
  const A = "http://schemas.openxmlformats.org/drawingml/2006/main";

  const themeXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office Theme">
    <a:themeElements>
      <a:clrScheme name="Office">
        <a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>
        <a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>
        <a:dk2><a:srgbClr val="0E2841"/></a:dk2>
        <a:lt2><a:srgbClr val="E8EEF5"/></a:lt2>
        <a:accent1><a:srgbClr val="1E40AF"/></a:accent1>
        <a:accent2><a:srgbClr val="EA580C"/></a:accent2>
        <a:accent3><a:srgbClr val="64748B"/></a:accent3>
        <a:accent4><a:srgbClr val="0F766E"/></a:accent4>
        <a:accent5><a:srgbClr val="0369A1"/></a:accent5>
        <a:accent6><a:srgbClr val="4338CA"/></a:accent6>
        <a:hlink><a:srgbClr val="1D4ED8"/></a:hlink>
        <a:folHlink><a:srgbClr val="6D28D9"/></a:folHlink>
      </a:clrScheme>
    </a:themeElements>
  </a:theme>`;

  const masterXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>
    <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
    <p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
  </p:sldMaster>`;

  const layoutXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">
    <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>
  </p:sldLayout>`;

  const slide1Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="CoverBg"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="${emu(960)}" cy="${emu(540)}"/></a:xfrm><a:solidFill><a:srgbClr val="0F172A"/></a:solidFill></p:spPr>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="UnitHeading"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(70)}"/><a:ext cx="${emu(820)}" cy="${emu(48)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2400" b="1"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:rPr><a:t>UNIT 5. PLACES AND HOW TO GET THERE</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="LessonHeading"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(130)}"/><a:ext cx="${emu(820)}" cy="${emu(56)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="3200" b="1"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:rPr><a:t>LESSON 3 HOW FAR IS THIS…?</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="HowToPlay"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(220)}"/><a:ext cx="${emu(400)}" cy="${emu(40)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800" b="1"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:rPr><a:t>How to play</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="6" name="WrapUpLead"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(300)}"/><a:ext cx="${emu(400)}" cy="${emu(40)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1800"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:rPr><a:t>and we can …</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slide2Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="DarkBanner"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="0" y="${emu(85)}"/><a:ext cx="${emu(960)}" cy="${emu(280)}"/></a:xfrm><a:solidFill><a:schemeClr val="dk1"/></a:solidFill></p:spPr>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="DivNum"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(98)}"/><a:ext cx="${emu(120)}" cy="${emu(68)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="4800" b="1"><a:solidFill><a:srgbClr val="EA580C"/></a:solidFill></a:rPr><a:t>04</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="DivHead"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(174)}"/><a:ext cx="${emu(700)}" cy="${emu(48)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:lstStyle><a:lvl1pPr><a:defRPr sz="2800" b="1"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:defRPr></a:lvl1pPr></a:lstStyle><a:p><a:r><a:t>Conversation</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="DivSub"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(236)}"/><a:ext cx="${emu(800)}" cy="${emu(56)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:lstStyle><a:lvl1pPr><a:defRPr sz="2800"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:defRPr></a:lvl1pPr></a:lstStyle><a:p><a:r><a:t>Talk about distance and means of transportation</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slide3Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="DarkBanner2"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="0" y="${emu(85)}"/><a:ext cx="${emu(960)}" cy="${emu(280)}"/></a:xfrm><a:solidFill><a:srgbClr val="1E293B"/></a:solidFill></p:spPr>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="DivNum2"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(98)}"/><a:ext cx="${emu(120)}" cy="${emu(68)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="4800" b="1"><a:solidFill><a:srgbClr val="EA580C"/></a:solidFill></a:rPr><a:t>02</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="DivHead2"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(174)}"/><a:ext cx="${emu(700)}" cy="${emu(48)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2800" b="1"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:rPr><a:t>GRAMMAR</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="DivSub2"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(60)}" y="${emu(236)}"/><a:ext cx="${emu(800)}" cy="${emu(56)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2800"><a:solidFill><a:schemeClr val="bg1"/></a:solidFill></a:rPr><a:t>Questions with “How far…?”</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slide4Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="TrackListen"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(20)}"/><a:ext cx="${emu(880)}" cy="${emu(30)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400" b="1"/><a:t>[U5L3_Track 2] Listen and repeat.</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="PairsInst"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(54)}"/><a:ext cx="${emu(880)}" cy="${emu(30)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"/><a:t>Now, work in pairs and practice the conversation.</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="QuestionPrompt"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(88)}"/><a:ext cx="${emu(880)}" cy="${emu(30)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"/><a:t>Can you add more words to each group?</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="GrammarTheory"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(124)}"/><a:ext cx="${emu(880)}" cy="${emu(112)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1600" b="1"/><a:t>Questions with How far…</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>To ask about distance or travel time between places.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400"/><a:t>How far: ask about distance between two places.</a:t></a:r></a:p>
          <a:p><a:r><a:rPr sz="1400" b="1"/><a:t>Structure:</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="6" name="SubModel"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(248)}"/><a:ext cx="${emu(220)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400" b="1"/><a:t>MODEL</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="7" name="SubActivator"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(280)}" y="${emu(248)}"/><a:ext cx="${emu(220)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400" b="1"/><a:t>ACTIVATOR</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="8" name="SubVideo"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(520)}" y="${emu(248)}"/><a:ext cx="${emu(260)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400" b="1"/><a:t>VIDEO WATCHING</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="9" name="PaleCard36"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr>
          <a:xfrm><a:off x="${emu(40)}" y="${emu(286)}"/><a:ext cx="${emu(880)}" cy="${emu(58)}"/></a:xfrm>
          <a:solidFill><a:schemeClr val="tx2"><a:lumMod val="10000"/><a:lumOff val="90000"/></a:schemeClr></a:solidFill>
        </p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"/><a:t>Asking about means of transportation: How do you go to ….?</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="10" name="PushingPrompt"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(380)}"/><a:ext cx="${emu(520)}" cy="${emu(86)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/>
          <a:p><a:r><a:rPr sz="1600"/><a:t>Work in pairs and discuss how your team commutes every day across the city.</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="11" name="BottomUnmodified"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(482)}"/><a:ext cx="${emu(520)}" cy="${emu(34)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"/><a:t>I take the bus to work.</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slide5Xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
    <p:cSld><p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="HwBanner"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="0" y="${emu(15)}"/><a:ext cx="${emu(720)}" cy="${emu(50)}"/></a:xfrm><a:solidFill><a:srgbClr val="1E293B"/></a:solidFill></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="2000" b="1"><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill></a:rPr><a:t>HOMEWORK &amp; LESSON PREPARATION CHECK</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="HwInst"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(40)}" y="${emu(85)}"/><a:ext cx="${emu(700)}" cy="${emu(36)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1600" b="1"/><a:t>Look at the pictures. Write imperatives.</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="4" name="BlankHost"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(80)}" y="${emu(320)}"/><a:ext cx="${emu(260)}" cy="${emu(30)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"/><a:t>1. ______________</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="5" name="AnswerReveal"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="${emu(105)}" y="${emu(312)}"/><a:ext cx="${emu(200)}" cy="${emu(26)}"/></a:xfrm><a:noFill/></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr sz="1400"/><a:t>Take the train.</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree></p:cSld>
  </p:sld>`;

  const slides = [slide1Xml, slide2Xml, slide3Xml, slide4Xml, slide5Xml];
  const z = new slEnv.JSZip();
  z.file("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-officedocument.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>`);
  z.file("ppt/presentation.xml", `<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="${P}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId10"/></p:sldMasterIdLst><p:sldIdLst>${slides.map((_, i) => `<p:sldId id="${256 + i}" r:id="rId${i + 1}"/>`).join("")}</p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/></p:presentation>`);
  z.file("ppt/_rels/presentation.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>${slides.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide${i + 1}.xml"/>`).join("")}</Relationships>`);
  z.file("ppt/theme/theme1.xml", themeXml);
  z.file("ppt/slideMasters/slideMaster1.xml", masterXml);
  z.file("ppt/slideMasters/_rels/slideMaster1.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>`);
  z.file("ppt/slideLayouts/slideLayout1.xml", layoutXml);
  z.file("ppt/slideLayouts/_rels/slideLayout1.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/></Relationships>`);
  slides.forEach((xml, i) => {
    z.file(`ppt/slides/slide${i + 1}.xml`, xml);
    z.file(`ppt/slides/_rels/slide${i + 1}.xml.rels`, `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>`);
  });

  const u8 = await z.generateAsync({ type: "uint8array" });
  const ab = u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

  const origWarn = console.warn;
  const origErr = console.error;
  const layoutSolveErrors = [];
  console.warn = (...args) => { const s = args.map(String).join(" "); if (s.includes("[SL] layout solve")) layoutSolveErrors.push(s); origWarn(...args); };
  console.error = (...args) => { const s = args.map(String).join(" "); if (s.includes("[SL] layout solve")) layoutSolveErrors.push(s); origErr(...args); };
  const out = await SlideLingo.convert(ab, "ja", async text => `JA:${text}`);
  console.warn = origWarn;
  console.error = origErr;

  assert.equal(layoutSolveErrors.length, 0, `Không được phát sinh lỗi layout solve: ${layoutSolveErrors.join("; ")}`);
  assert.equal(out.report.notes, 0, "Không được rơi bản dịch xuống Speaker Notes");
  assert.ok((SlideLingo.lastLayoutLog || []).every(l => (l.collisions || []).length === 0), "Mọi slide phải có collisions === 0");

  const outZip = await slEnv.JSZip.loadAsync(out.bytes);
  const readRuns = async slideIdx => {
    const xml = await outZip.file(`ppt/slides/slide${slideIdx}.xml`).async("string");
    const doc = new slEnv.DOMParser().parseFromString(xml, "application/xml");
    const I = SlideLingo._internals;
    return I.descendants(doc, A, "r").map(r => {
      const text = I.descendants(r, A, "t").map(t => t.textContent).join("");
      const sf = I.child(I.child(r, A, "rPr"), A, "solidFill");
      const hex = I.child(sf, A, "srgbClr")?.getAttribute("val")?.toUpperCase() || null;
      return { text, hex };
    });
  };

  // Slide 1 Cover
  const s1Xml = await outZip.file("ppt/slides/slide1.xml").async("string");
  assert.ok(s1Xml.includes("JA:Places And How To Get There"), "Slide 1: phải dịch UNIT 5. PLACES AND HOW TO GET THERE");
  assert.ok(s1Xml.includes("第3課：JA:How Far Is This…?"), "Slide 1: phải dịch LESSON 3 HOW FAR IS THIS…?");
  assert.ok(s1Xml.includes("(遊び方)"), "Slide 1: phải dịch How to play");
  assert.ok(s1Xml.includes("そして、次のことができるようになりました…"), "Slide 1: phải dịch and we can …");

  // Slide 2 & Slide 3 Section Dividers (numSp 04 / 02 + defRPr sz=2800 + sysClr bg1 -> #FFFFFF)
  const s2Runs = await readRuns(2);
  assert.ok(s2Runs.some(r => r.text.includes("会話") && r.hex === "FFFFFF"), "Slide 2: 04 Conversation phải dịch màu #FFFFFF");
  assert.ok(s2Runs.some(r => r.text.includes("JA:Talk about distance and means of transportation") && r.hex === "FFFFFF"), "Slide 2: subtitle section divider (defRPr + sysClr) phải dịch màu #FFFFFF");

  const s3Runs = await readRuns(3);
  assert.ok(s3Runs.some(r => r.text.includes("文法") && r.hex === "FFFFFF"), "Slide 3: 02 GRAMMAR phải dịch màu #FFFFFF");
  assert.ok(s3Runs.some(r => r.text.includes("JA:Questions with 「How far…?」") && r.hex === "FFFFFF"), "Slide 3: Questions with “How far…?” phải dịch màu #FFFFFF");

  // Slide 4 Track prefix, prompts, grammar explanations, short headings, pale lumMod/lumOff card (#1D4ED8), & bounds compaction
  const s4Runs = await readRuns(4);
  const s4Xml = await outZip.file("ppt/slides/slide4.xml").async("string");
  assert.ok(s4Xml.includes("[U5L3_Track 2] Listen and repeat.") && s4Xml.includes("JA:Listen and repeat.") && !s4Xml.includes("JA:[U5L3_Track 2]"), "Slide 4: giữ [U5L3_Track 2] tiếng Anh và chỉ dịch Listen and repeat.");
  assert.ok(s4Xml.includes("JA:Now, work in pairs and practice the conversation."), "Slide 4: dịch Now, work in pairs...");
  assert.ok(s4Xml.includes("JA:Can you add more words to each group?"), "Slide 4: dịch Can you add more words to each group?");
  assert.ok(s4Xml.includes("JA:Questions with How far…"), "Slide 4: dịch Questions with How far…");
  assert.ok(s4Xml.includes("JA:To ask about distance or travel time between places."), "Slide 4: dịch To ask about...");
  assert.ok(s4Xml.includes("JA:How far: ask about distance between two places."), "Slide 4: dịch How far: ask about...");
  assert.ok(s4Xml.includes("(構文)"), "Slide 4: dịch Structure:");
  assert.ok(s4Xml.includes("(モデル)") && s4Xml.includes("(アクティビティ)") && s4Xml.includes("(動画視聴)"), "Slide 4: dịch MODEL / ACTIVATOR / VIDEO WATCHING");
  assert.ok(s4Runs.some(r => r.text.includes("JA:Asking about means of transportation") && r.hex === "1D4ED8"), "Slide 4: thẻ lumMod/lumOff nền nhạt phải chọn màu dịch #1D4ED8 (không phải #FFFFFF)");
  assert.ok(!s4Xml.includes("JA:I take the bus to work."), "Slide 4: ví dụ gốc phía dưới không bị dịch sai và đẩy vượt đáy");

  // Slide 5 Blank-line answer-key guard
  const s5Xml = await outZip.file("ppt/slides/slide5.xml").async("string");
  assert.ok(s5Xml.includes("宿題・レッスン準備の確認") && s5Xml.includes("JA:Look at the pictures. Write imperatives."), "Slide 5: dịch tiêu đề HOMEWORK & Look at the pictures");
  assert.ok(!s5Xml.includes("JA:Take the train."), "Slide 5: không dịch đáp án nằm đè lên chỗ trống ______");
});

await test("Hộp thông báo Changelog theo version: mặc định ẩn (hidden), bấm mở/ẩn & đồng bộ với CHANGELOG.md", () => {
  assert.match(html, /<button\b[^>]*id="changelog-trigger"[^>]*aria-expanded="false"/, "Nút mở Changelog phải có aria-expanded=\"false\" lúc mới tải");
  assert.match(html, /<div class="changelog-layer" id="changelog-layer" hidden>/, "#changelog-layer phải mang thuộc tính hidden để ẩn mặc định");
  assert.ok(html.includes('id="changelog-close-btn"'), "Hộp Changelog phải có nút đóng/ẩn #changelog-close-btn");

  const metaIdx = scriptMatches[2].indexOf("const APP_VERSION =");
  assert.ok(metaIdx > 0, "Phải có khai báo APP_VERSION trong <script> thứ 3");
  const iifeStart = scriptMatches[2].lastIndexOf("(() => {", metaIdx);
  assert.ok(iifeStart > 0, "Phải tìm thấy IIFE quản lý Changelog");
  const changelogSnippet = scriptMatches[2].slice(iifeStart);

  const elements = new Map();
  const makeStubEl = (id) => ({
    id,
    hidden: id === "changelog-layer" || id === "changelog-unread-dot",
    textContent: "",
    className: "",
    style: {},
    attributes: {},
    children: [],
    classList: {
      set: new Set(),
      add(c) { this.set.add(c); },
      remove(c) { this.set.delete(c); },
      toggle(c, f) { if (f) this.set.add(c); else this.set.delete(c); },
      contains(c) { return this.set.has(c); },
    },
    setAttribute(k, v) { this.attributes[k] = String(v); },
    getAttribute(k) { return this.attributes[k] ?? null; },
    addEventListener(evt, fn) { this[`_on_${evt}`] = fn; },
    getBoundingClientRect() { return { left: 24, bottom: 52, top: 28, width: 120, height: 24 }; },
    appendChild(child) { this.children.push(child); },
    append(...nodes) { this.children.push(...nodes); },
    focus() {},
    offsetWidth: 420,
  });
  for (const id of ["changelog-trigger", "changelog-pill-ver", "changelog-unread-dot", "changelog-layer", "changelog-scrim", "changelog-drawer", "changelog-list", "changelog-close-btn"]) {
    elements.set(id, makeStubEl(id));
  }
  const storage = new Map();
  const sandbox = {
    globalThis: null,
    $: id => elements.get(id) || null,
    document: {
      createElement: () => makeStubEl(""),
      addEventListener() {},
    },
    window: { innerWidth: 1280, innerHeight: 800, addEventListener() {} },
    localStorage: {
      getItem: k => storage.get(k) ?? null,
      setItem: (k, v) => storage.set(k, String(v)),
    },
    setTimeout: () => 1,
    clearTimeout: () => {},
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(changelogSnippet, sandbox);

  const meta = sandbox.APP_RELEASE_META;
  assert.ok(meta && /^v\d+\.\d+\.\d+$/.test(meta.version), "APP_VERSION phải đúng chuẩn vX.Y.Z");
  assert.ok(Array.isArray(meta.changelog) && meta.changelog.length >= 1, "APP_CHANGELOG phải chứa ít nhất 1 phiên bản");
  assert.equal(meta.changelog[0].version, meta.version, "Phiên bản đầu bảng APP_CHANGELOG phải khớp APP_VERSION");

  for (const entry of meta.changelog) {
    assert.ok(/^v\d+\.\d+\.\d+$/.test(entry.version), `Version không hợp lệ: ${entry.version}`);
    assert.ok(typeof entry.date === "string" && entry.date.trim().length > 0, `Thiếu date cho ${entry.version}`);
    assert.ok(typeof entry.tag === "string" && entry.tag.trim().length > 0, `Thiếu tag cho ${entry.version}`);
    assert.ok(typeof entry.title === "string" && entry.title.trim().length > 0, `Thiếu title cho ${entry.version}`);
    assert.ok(Array.isArray(entry.items) && entry.items.length > 0 && entry.items.every(s => typeof s === "string" && s.trim().length > 0), `Thiếu items cho ${entry.version}`);
  }

  assert.ok(elements.get("changelog-layer").hidden === true, "Sau khởi tạo hộp Changelog vẫn phải ẩn");
  elements.get("changelog-trigger")._on_click({ stopPropagation() {} });
  assert.equal(elements.get("changelog-layer").hidden, false, "Bấm #changelog-trigger phải hiện hộp Changelog");
  assert.equal(elements.get("changelog-trigger").getAttribute("aria-expanded"), "true");
  assert.equal(storage.get("2mybebi_seen_changelog_ver"), meta.version, "Mở xem phải lưu version đã đọc vào localStorage");
  elements.get("changelog-close-btn")._on_click();
  assert.equal(elements.get("changelog-trigger").getAttribute("aria-expanded"), "false", "Bấm Ẩn phải thu gọn hộp Changelog");

  assert.ok(html.includes(`id="changelog-pill-ver">${meta.version}<`), "Badge HTML #changelog-pill-ver phải khớp APP_VERSION");
  const changelogMd = readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
  assert.ok(changelogMd.includes(`## ${meta.version}`), "CHANGELOG.md phải ghi nhận mục tương ứng APP_VERSION");
});

console.log(`\nHoàn tất: ${passed}/${passed} bài kiểm thử đã PASS!\n`);

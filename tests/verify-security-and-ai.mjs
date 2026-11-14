import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
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

  for (const badPath of [
    "ppt/vbaProject.bin",
    "ppt/vbaData.xml",
    "_xmlsignatures/sig1.xml",
    "ppt/activeX/activeX1.xml",
    "ppt/embeddings/oleObject1.bin",
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

console.log(`\nHoàn tất: ${passed}/${passed} bài kiểm thử đã PASS!\n`);

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
  for (const hdr of ["Starting/Answering a call", "Asking for someone", "Leaving a message", "Taking a message", "Checking details", "Ending a call"]) {
    assert.ok(resXml.includes(`(VN:${hdr})`), `Tiêu đề bảng "${hdr}" phải được dịch gọn trong ngoặc`);
  }
  assert.ok(resXml.includes("VN:Could I leave a message?"), "Khung câu hàng 2 phải được dịch đồng bộ");
  assert.ok(resXml.includes("VN:OK. Thanks."), "Khung câu hàng 3 phải được dịch đồng bộ");

  const resDoc = new slEnv.DOMParser().parseFromString(resXml, "application/xml");
  const P = "http://schemas.openxmlformats.org/presentationml/2006/main";
  const A = "http://schemas.openxmlformats.org/drawingml/2006/main";
  const sps = Array.from(resDoc.getElementsByTagNameNS(P, "sp"));
  const findSp = name => sps.find(s => s.getElementsByTagNameNS(P, "cNvPr")[0]?.getAttribute("name") === name);

  // Kiểm tra màu bản dịch phân biệt theo màu chữ gốc
  const runColorOf = (sp, matchText) => {
    const runs = Array.from(sp.getElementsByTagNameNS(A, "r"));
    const targetRun = runs.find(r => (r.textContent || "").includes(matchText));
    return targetRun?.getElementsByTagNameNS(A, "srgbClr")[0]?.getAttribute("val");
  };
  assert.equal(runColorOf(findSp("SubCyan"), "VN:Key expressions"), "B4235A", "Chữ gốc màu xanh lam sáng #3AD0EC trên nền sáng phải dùng bản dịch màu Rose-Berry B4235A, không được dùng vàng FEF08A");
  assert.equal(runColorOf(findSp("DarkBtn"), "Luyện tập"), "FEF08A", "Chữ gốc màu trắng #FFFFFF trên nền tối phải dùng bản dịch màu vàng ấm FEF08A");
  assert.equal(runColorOf(findSp("CellBoxR0C0"), "VN:Hello / Hi."), "1D4ED8", "Chữ gốc màu đen #000000 phải dùng bản dịch màu Cobalt Blue 1D4ED8");

  // Kiểm tra khung CellBoxR0C1 (7 dòng dày) không leo lên tiêu đề "Asking for someone" (y>=115pt) và không tràn xuống hàng 2 (y+h<=232pt)
  const r0c1 = findSp("CellBoxR0C1");
  const r0c1Y = Number(r0c1.getElementsByTagNameNS(A, "off")[0].getAttribute("y")) / PT;
  const r0c1H = Number(r0c1.getElementsByTagNameNS(A, "ext")[0].getAttribute("cy")) / PT;
  assert.ok(r0c1Y >= 114, `CellBoxR0C1 (y=${r0c1Y.toFixed(1)}pt) phải nằm dưới tiêu đề Asking for someone`);
  assert.ok(r0c1Y + r0c1H <= 232, `CellBoxR0C1 (bottom=${(r0c1Y + r0c1H).toFixed(1)}pt) không được tràn qua đáy hàng 1 (232pt) xuống Taking a message`);
  assert.ok(r0c1.getElementsByTagNameNS(A, "normAutofit").length >= 1, "CellBoxR0C1 phải được gắn <a:normAutofit/> chuẩn ECMA-376");
  const scaledSizes = Array.from(r0c1.getElementsByTagNameNS(A, "rPr")).map(r => Number(r.getAttribute("sz"))).filter(Boolean);
  assert.ok(scaledSizes.some(sz => sz < 1400), `CellBoxR0C1 phải tự co font size nhỏ hơn 14pt để vừa ô: [${scaledSizes.join(",")}]`);
});

console.log(`\nHoàn tất: ${passed}/${passed} bài kiểm thử đã PASS!\n`);

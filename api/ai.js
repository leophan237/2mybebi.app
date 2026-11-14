"use strict";

const crypto = require("crypto");

const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";
const LOCKED_PROVIDER = "openrouter";
const LOCKED_MODEL = "openai/gpt-6-luna";
const MAX_BODY_BYTES = 262144; // 256 KB
const MAX_PROMPT_CHARS = 160000;
const RATE_WINDOW_MS = 60000;
const RATE_MAX_REQUESTS = 40;

const rateBuckets = new Map();

function redactSecrets(input, extraSecrets = []) {
  let out = String(input ?? "");
  for (const s of extraSecrets) {
    if (s && typeof s === "string" && s.length >= 6) {
      out = out.split(s).join("[REDACTED]");
    }
  }
  return out
    .replace(/sk-or-v1-[A-Za-z0-9_-]{8,}/g, "[REDACTED_KEY]")
    .replace(/sk-(?:proj-|ant-)?[A-Za-z0-9_-]{14,}/g, "[REDACTED_KEY]")
    .replace(/AIza[0-9A-Za-z_-]{20,}/g, "[REDACTED_KEY]")
    .replace(/Bearer\s+[A-Za-z0-9._-]{10,}/gi, "Bearer [REDACTED]")
    .replace(/([?&](?:key|api_key|token)=)[^&\s"']+/gi, "$1[REDACTED]");
}

function getClientIp(req) {
  const fwd = req.headers?.["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.trim()) {
    return fwd.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function checkRateLimit(ip, now = Date.now()) {
  if (rateBuckets.size > 1000) {
    for (const [k, v] of rateBuckets.entries()) {
      if (now - v.start >= RATE_WINDOW_MS) rateBuckets.delete(k);
    }
  }
  const bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.start >= RATE_WINDOW_MS) {
    rateBuckets.set(ip, { start: now, count: 1 });
    return { allowed: true, remaining: RATE_MAX_REQUESTS - 1, resetSec: 60 };
  }
  bucket.count += 1;
  if (bucket.count > RATE_MAX_REQUESTS) {
    const resetSec = Math.max(1, Math.ceil((RATE_WINDOW_MS - (now - bucket.start)) / 1000));
    return { allowed: false, remaining: 0, resetSec };
  }
  return {
    allowed: true,
    remaining: RATE_MAX_REQUESTS - bucket.count,
    resetSec: Math.ceil((RATE_WINDOW_MS - (now - bucket.start)) / 1000),
  };
}

function extractHost(urlStr) {
  try {
    return new URL(urlStr).host.toLowerCase();
  } catch {
    return "";
  }
}

function isOriginAllowed(req) {
  const origin = req.headers?.origin || "";
  const referer = req.headers?.referer || "";
  const rawSource = origin || referer;
  if (!rawSource) {
    // Allow direct curl/health/same-server calls only when Origin/Referer absent?
    // For browser POST requests Origin is always sent; require Fetch-Site / same-host fallback for GET.
    return req.method === "GET";
  }
  const sourceHost = extractHost(rawSource);
  if (!sourceHost) return false;

  const reqHost = String(req.headers?.["x-forwarded-host"] || req.headers?.host || "").toLowerCase();
  if (reqHost && sourceHost === reqHost) return true;

  if (/^(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(sourceHost)) return true;

  const extra = String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  for (const allowed of extra) {
    const allowedHost = extractHost(allowed) || allowed.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (allowedHost && sourceHost === allowedHost) return true;
  }
  return false;
}

function verifyPasscode(reqPasscode, configuredPasscode) {
  if (!configuredPasscode) return true;
  const a = crypto.createHash("sha256").update(String(reqPasscode || ""), "utf8").digest();
  const b = crypto.createHash("sha256").update(String(configuredPasscode), "utf8").digest();
  return crypto.timingSafeEqual(a, b);
}

async function readJsonBody(req) {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
    const approxLen = Buffer.byteLength(JSON.stringify(req.body), "utf8");
    if (approxLen > MAX_BODY_BYTES) throw Object.assign(new Error("Payload vượt quá 256 KB."), { statusCode: 413 });
    return req.body;
  }
  if (typeof req.body === "string") {
    if (Buffer.byteLength(req.body, "utf8") > MAX_BODY_BYTES) throw Object.assign(new Error("Payload vượt quá 256 KB."), { statusCode: 413 });
    return JSON.parse(req.body);
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw Object.assign(new Error("Payload vượt quá 256 KB."), { statusCode: 413 });
    }
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw.trim()) return {};
  return JSON.parse(raw);
}

function validateAiRequestPayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw Object.assign(new Error("Body phải là JSON object hợp lệ."), { statusCode: 400 });
  }
  const action = body.action === "test" ? "test" : "chat";
  if (action === "test") {
    return {
      action: "test",
      systemPrompt: 'You are a connectivity test. Output strictly valid JSON: {"ok": true}',
      userPrompt: 'Reply strictly with JSON {"ok": true}',
      maxTokens: 128,
      temperature: 0,
      jsonMode: true,
    };
  }
  const systemPrompt = typeof body.systemPrompt === "string" ? body.systemPrompt.trim() : "";
  const userPrompt = typeof body.userPrompt === "string" ? body.userPrompt.trim() : "";
  if (!systemPrompt || !userPrompt) {
    throw Object.assign(new Error("Thiếu systemPrompt hoặc userPrompt."), { statusCode: 400 });
  }
  if (systemPrompt.length + userPrompt.length > MAX_PROMPT_CHARS) {
    throw Object.assign(new Error("Nội dung gửi AI vượt quá giới hạn an toàn."), { statusCode: 413 });
  }
  const rawMax = Number(body.maxTokens);
  const maxTokens = Number.isFinite(rawMax) ? Math.max(64, Math.min(16384, Math.round(rawMax))) : 8192;
  const rawTemp = Number(body.temperature);
  const temperature = Number.isFinite(rawTemp) ? Math.max(0, Math.min(0.7, rawTemp)) : 0.2;
  const jsonMode = body.jsonMode !== false;

  return { action: "chat", systemPrompt, userPrompt, maxTokens, temperature, jsonMode };
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("X-Content-Type-Options", "nosniff");
  for (const [k, v] of Object.entries(extraHeaders)) {
    res.setHeader(k, v);
  }
  res.end(JSON.stringify(payload));
}

async function handler(req, res) {
  const apiKey = String(process.env.OPENROUTER_API_KEY || "").trim();
  const configuredPasscode = String(process.env.APP_ACCESS_CODE || "").trim();

  if (req.method === "GET") {
    return sendJson(res, 200, {
      ok: true,
      configured: Boolean(apiKey),
      passcodeRequired: Boolean(configuredPasscode),
      provider: LOCKED_PROVIDER,
      model: LOCKED_MODEL,
    });
  }

  if (req.method !== "POST") {
    return sendJson(res, 405, { ok: false, error: "Method Not Allowed" }, { Allow: "GET, POST" });
  }

  if (!isOriginAllowed(req)) {
    return sendJson(res, 403, { ok: false, error: "Nguồn truy cập không được phép (Origin blocked)." });
  }

  const rl = checkRateLimit(getClientIp(req));
  if (!rl.allowed) {
    return sendJson(
      res,
      429,
      { ok: false, error: `Quá nhiều yêu cầu từ máy này. Vui lòng thử lại sau ${rl.resetSec} giây.` },
      { "Retry-After": String(rl.resetSec) }
    );
  }

  if (!verifyPasscode(req.headers?.["x-app-passcode"], configuredPasscode)) {
    return sendJson(res, 401, {
      ok: false,
      requiresPasscode: true,
      error: "Mã truy cập máy chưa đúng hoặc chưa được nhập.",
    });
  }

  if (!apiKey) {
    return sendJson(res, 503, {
      ok: false,
      notConfigured: true,
      error: "Máy chủ chưa cấu hình OPENROUTER_API_KEY trên Vercel Environment Variables.",
    });
  }

  let validated;
  try {
    const rawBody = await readJsonBody(req);
    validated = validateAiRequestPayload(rawBody);
  } catch (err) {
    return sendJson(res, err?.statusCode || 400, {
      ok: false,
      error: redactSecrets(err?.message || "Dữ liệu yêu cầu không hợp lệ.", [apiKey]),
    });
  }

  const upstreamPayload = {
    model: LOCKED_MODEL,
    messages: [
      { role: "system", content: validated.systemPrompt },
      { role: "user", content: validated.userPrompt },
    ],
    temperature: validated.temperature,
    max_tokens: validated.maxTokens,
    ...(validated.jsonMode ? { response_format: { type: "json_object" } } : {}),
  };

  const refererHdr = String(req.headers?.origin || `https://${req.headers?.host || "2mybebi.vercel.app"}`);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), validated.action === "test" ? 20000 : 55000);

  try {
    let upstreamRes = await fetch(OPENROUTER_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
        "HTTP-Referer": refererHdr,
        "X-Title": "2mybebi Bilingual Lesson Studio",
      },
      body: JSON.stringify(upstreamPayload),
      signal: controller.signal,
    });

    if (!upstreamRes.ok && upstreamPayload.response_format && upstreamRes.status === 400) {
      const retryErrText = await upstreamRes.text().catch(() => "");
      if (/response_format|json_object/i.test(retryErrText)) {
        delete upstreamPayload.response_format;
        upstreamRes = await fetch(OPENROUTER_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiKey}`,
            "HTTP-Referer": refererHdr,
            "X-Title": "2mybebi Bilingual Lesson Studio",
          },
          body: JSON.stringify(upstreamPayload),
          signal: controller.signal,
        });
      }
    }

    if (!upstreamRes.ok) {
      const rawErr = await upstreamRes.text().catch(() => "");
      let detail = "";
      try {
        const j = JSON.parse(rawErr);
        detail = j?.error?.message || j?.message || "";
      } catch {
        detail = rawErr.slice(0, 220);
      }
      const cleanDetail = redactSecrets(detail, [apiKey, configuredPasscode]);
      const retryAfter = upstreamRes.headers.get("retry-after");
      const extraHdrs = retryAfter ? { "Retry-After": retryAfter } : {};
      return sendJson(
        res,
        upstreamRes.status >= 400 && upstreamRes.status < 600 ? upstreamRes.status : 502,
        {
          ok: false,
          error: `OpenRouter (${LOCKED_MODEL}) báo lỗi HTTP ${upstreamRes.status}${cleanDetail ? ": " + cleanDetail : ""}`,
        },
        extraHdrs
      );
    }

    const data = await upstreamRes.json();
    const choice = data?.choices?.[0];
    const content = typeof choice?.message?.content === "string" ? choice.message.content : "";
    if (!content) {
      return sendJson(res, 502, { ok: false, error: "OpenRouter trả về phản hồi rỗng." });
    }

    return sendJson(res, 200, {
      ok: true,
      provider: LOCKED_PROVIDER,
      model: LOCKED_MODEL,
      content,
      finishReason: choice?.finish_reason || "",
    });
  } catch (err) {
    const isAbort = err?.name === "AbortError";
    return sendJson(res, isAbort ? 504 : 502, {
      ok: false,
      error: isAbort
        ? "OpenRouter phản hồi quá thời gian chờ."
        : redactSecrets(`Lỗi kết nối tới OpenRouter (${err?.message || "Network Error"}).`, [apiKey, configuredPasscode]),
    });
  } finally {
    clearTimeout(timeout);
  }
}

handler._internals = {
  LOCKED_PROVIDER,
  LOCKED_MODEL,
  redactSecrets,
  checkRateLimit,
  isOriginAllowed,
  verifyPasscode,
  validateAiRequestPayload,
};

module.exports = handler;

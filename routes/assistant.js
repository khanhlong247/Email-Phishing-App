const express = require("express");
const router = express.Router();
require("dotenv").config();
const { GoogleGenerativeAI } = require("@google/generative-ai");
const crypto = require("crypto");

const GEMINI_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_KEY) console.warn("GEMINI_API_KEY not set in .env");

const genAI = new GoogleGenerativeAI(GEMINI_KEY);

// ===== Session & pending store (cookie 'pgid') =====
const pendingBySession = new Map();
function parseCookies(req) {
  const out = {};
  const rc = req.headers.cookie;
  if (!rc) return out;
  rc.split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > -1)
      out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
function ensureSessionId(req, res) {
  const cookies = parseCookies(req);
  let id = cookies.pgid;
  if (!id) {
    id = crypto.randomBytes(16).toString("hex");
    res.setHeader("Set-Cookie", `pgid=${id}; HttpOnly; Path=/; SameSite=Lax`);
  }
  return id;
}
function setPending(sessionId, original, url) {
  pendingBySession.set(sessionId, { original, url, ts: Date.now() });
}
function getPending(sessionId) {
  const p = pendingBySession.get(sessionId);
  if (!p) return null;
  if (Date.now() - p.ts > 10 * 60 * 1000) {
    pendingBySession.delete(sessionId);
    return null;
  }
  return p;
}
function clearPending(sessionId) {
  pendingBySession.delete(sessionId);
}

// ===== Helpers =====
const KEYWORD_RE = /\b(kiểm\s*tra|check|scan|xem\s*giúp|xem\s*hộ)\b/i;

function explicitCheckRequested(text) {
  if (!text) return false;
  return KEYWORD_RE.test(text.toLowerCase());
}
function isAffirmative(text) {
  if (!text) return false;
  return /\b(có|ok|đồng\s*ý|được|okie|yes|y|đồngy|duoc)\b/i.test(text.trim());
}
function isMailChoice(text) {
  if (!text) return false;
  return /\b(mail|email|thư|toàn\s*bộ|full)\b/i.test(text.trim());
}
function isUrlChoice(text) {
  if (!text) return false;
  return /\b(url|link)\b/i.test(text.trim());
}
function isKnowledgeQuery(text) {
  if (!text) return false;
  const t = text.toLowerCase();
  if (/[?¿]$/.test(t)) return true;
  return /\b(phishing|bảo\s*mật|an\s*toàn\s*thông\s*tin|social\s*engineering|mật\s*khẩu|password|2fa|mfa|otp|ssl|https|url\s*rút\s*gọn|malware|ransomware|virus|spyware|email\s*giả\s*mạo|best\s*practice|là\s*gì|làm\s*sao|làm\s*thế\s*nào|cách|hướng\s*dẫn|tại\s*sao|vì\s*sao)\b/.test(
    t
  );
}
function extractQuoted(text) {
  const m = text.match(/"([^"]+)"/);
  return m ? m[1] : null;
}
function extractFirstUrl(text) {
  if (!text) return null;
  const m = text.match(/https?:\/\/[^\s"'<>]+/i);
  return m ? m[0].replace(/[),.;!?]+$/, "") : null;
}
function hasUrlAndMore(text) {
  const url = extractFirstUrl(text);
  if (!url) return { url: null, more: false };
  const onlyUrl = text.trim() === url.trim();
  return { url, more: !onlyUrl };
}
function tailAfterKeyword(text) {
  if (!text) return "";
  const m = text.match(KEYWORD_RE);
  if (!m) return "";
  return text.slice(m.index + m[0].length).trim();
}
function isBareUrlString(s) {
  if (!s) return false;
  const url = extractFirstUrl(s);
  return !!url && s.trim() === url;
}

// ===== Prompt builders =====
function buildPromptCheck(content, userInput, forceType = null) {
  const urlOnly = /^https?:\/\/[^\s"'<>]+$/i.test(content);
  const typeHint = forceType || (urlOnly ? "url" : "url|email|text");
  return `
Bạn là "PhishGuard", một trợ lý an ninh mạng (tiếng Việt) chuyên phân tích phishing với URL, email và văn bản.

QUY ƯỚC:
- Bất kỳ nội dung trong dấu nháy kép "..." phải kiểm tra ngay, không hỏi lại.
- Nếu người dùng có từ khóa "kiểm tra"/"check"/"scan"/"xem giúp" thì kiểm tra ngay.
- Nếu đang phân tích URL đơn lẻ, TẬP TRUNG kiểm tra URL đó (không phân tích phần chữ xung quanh).

ĐỊNH DẠNG TRẢ LỜI KHI KIỂM TRA (BẮT BUỘC):
1) Dòng đầu tiên: kết quả rõ ràng, CHỌN DUY NHẤT MỘT:
   - ✅ An toàn
   - ⚠️ Có dấu hiệu phishing
2) Các dòng kế tiếp: giải thích ngắn gọn (1–3 câu), nêu lý do chính và khuyến nghị an toàn (nếu cần).
3) Dòng cuối cùng: JSON CHUẨN DUY NHẤT 1 dòng, KHÔNG bọc trong \`\`\` hay \`\`\`json, KHÔNG có chữ nào sau JSON:
   {"type":"${typeHint}","isPhishing":true|false,"confidence":0-100,"explanation":"lý do ngắn"}

RÀNG BUỘC NGHIÊM NGẶT:
- TUYỆT ĐỐI KHÔNG dùng \`\`\` hay \`\`\`json.
- KHÔNG thêm chữ sau JSON. KHÔNG thiếu JSON. KHÔNG đổi thứ tự.
- JSON chỉ gồm 4 khóa: type, isPhishing, confidence, explanation.
- Nếu đang kiểm URL, đặt type="url" và tập trung các chỉ dấu: mạo danh/typosquatting, subdomain đánh lừa, unicode/homograph, IP-based, rút gọn link, tham số lạ, trang đăng nhập giả, certificate.
- Nếu đang kiểm cả đoạn mail, đặt type="email"; nếu chỉ là text thuần, đặt type="text".
- confidence là số nguyên 0..100.

THÔNG TIN THAM CHIẾU:
User input: ${userInput}
Nội dung cần kiểm tra: ${content}

TRẢ KẾT QUẢ THEO ĐÚNG ĐỊNH DẠNG TRÊN.
`;
}
function buildPromptAskIntro() {
  return `
Bạn là "PhishGuard", trợ lý an ninh mạng (tiếng Việt).
Xin chào 👋, mình là PhishGuard – trợ lý phát hiện phishing.
Quy ước: Bất kỳ nội dung bạn đặt trong dấu nháy kép "..." mình sẽ kiểm tra ngay (ví dụ: "https://chat.zalo.me/").
Nếu không đặt trong "..." và cũng không ghi rõ "kiểm tra", mình sẽ hỏi xác nhận.
Bạn muốn mình kiểm tra không? (gõ "có" để đồng ý)
Hoặc dán trực tiếp Mail/URL trong " " để mình kiểm tra ngay. Ví dụ "http://paypal.verify-account-login.com".
(Chỉ trả phần chat xác nhận, KHÔNG trả JSON)
`;
}
function buildPromptAskDisamb(userInput, url) {
  const mailQuoted = userInput.replace(/\s+/g, " ").trim();
  return `
Bạn là "PhishGuard", trợ lý an ninh mạng (tiếng Việt).
Mình phát hiện trong tin nhắn có URL: ${url}
Bạn muốn mình kiểm tra cả mail "${mailQuoted}" hay chỉ kiểm tra URL ${url}?
Gõ "mail" để kiểm tra toàn bộ nội dung, hoặc gõ "url" để chỉ kiểm tra đường link.
(Chỉ trả phần chat xác nhận, KHÔNG trả JSON)
`;
}
function buildPromptKnowledge(userInput) {
  return `
Bạn là "PhishGuard", trợ lý an ninh mạng (tiếng Việt).
Trả lời ngắn gọn, rõ ràng, thực dụng. Dùng gạch đầu dòng khi phù hợp. Không trả JSON.

YÊU CẦU:
- Nếu câu hỏi về phishing/an toàn thông tin (khái niệm, dấu hiệu, cách phòng tránh, best practices, 2FA/MFA, mật khẩu, link rút gọn, HTTPS/SSL, social engineering…), hãy trả lời như một chuyên gia thực hành.
- Ưu tiên: checklist hành động, dấu hiệu cảnh báo (red flags), ví dụ ngắn, bước kiểm tra nhanh.
- Tránh lý thuyết dài; tối đa 8–12 gạch đầu dòng; có thể nhóm theo mục.
- Nhắc nhẹ: “Nếu muốn mình kiểm tra thực tế, hãy dán nội dung trong dấu nháy kép "...".”

CÂU HỎI:
${userInput}
`;
}

// ===== Route =====
router.post("/", async (req, res) => {
  try {
    const sessionId = ensureSessionId(req, res);
    const userInput = req.body?.input ? String(req.body.input).trim() : "";
    const context = req.body?.context || null;
    const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

    // 1) Quoted => check immediately (prefer URL inside quotes)
    const quoted = extractQuoted(userInput);
    if (quoted) {
      clearPending(sessionId);
      const urlInQuoted = extractFirstUrl(quoted);
      const content = urlInQuoted || quoted;
      const forceType = urlInQuoted ? "url" : null;
      const prompt = buildPromptCheck(content, userInput, forceType);
      const result = await model.generateContent(prompt);
      return res.json({ output: result.response.text() });
    }

    // 2) Knowledge Q&A (when no URL present and looks like a knowledge question)
    if (!extractFirstUrl(userInput) && isKnowledgeQuery(userInput)) {
      clearPending(sessionId);
      const prompt = buildPromptKnowledge(userInput);
      const result = await model.generateContent(prompt);
      return res.json({ output: result.response.text() });
    }

    // 3) Choice mail/url (prefer context, else pending session)
    if (isMailChoice(userInput)) {
      const pend = context?.original
        ? { original: context.original }
        : getPending(sessionId);
      if (!pend?.original) {
        return res.json({
          output:
            'Bạn muốn kiểm tra gì? Gõ "url" hoặc "mail". Hoặc dán nội dung trong "..." để mình kiểm tra ngay.',
        });
      }
      clearPending(sessionId);
      const prompt = buildPromptCheck(pend.original, userInput, "email");
      const result = await model.generateContent(prompt);
      return res.json({ output: result.response.text() });
    }
    if (isUrlChoice(userInput)) {
      const pend = context?.original
        ? { original: context.original }
        : getPending(sessionId);
      const src = pend?.original || "";
      const url = extractFirstUrl(src);
      if (!url) {
        return res.json({
          output:
            'Mình chưa thấy URL trong nội dung trước đó. Dán URL trong "..." (ví dụ: "http://example.com") để mình kiểm tra ngay.',
        });
      }
      clearPending(sessionId);
      const prompt = buildPromptCheck(url, userInput, "url");
      const result = await model.generateContent(prompt);
      return res.json({ output: result.response.text() });
    }

    // 4) Affirmative "có": if previous had URL+more -> disamb; else check
    if (isAffirmative(userInput)) {
      const src = context?.original || getPending(sessionId)?.original || "";
      if (src) {
        const { url, more } = hasUrlAndMore(src);
        if (url && more) {
          setPending(sessionId, src, url);
          const dis = buildPromptAskDisamb(src, url);
          return res.json({ output: dis });
        }
        clearPending(sessionId);
        const content = url || src;
        const forceType = url ? "url" : null;
        const prompt = buildPromptCheck(content, userInput, forceType);
        const result = await model.generateContent(prompt);
        return res.json({ output: result.response.text() });
      }
      return res.json({
        output:
          'Mình đã sẵn sàng kiểm tra. Dán nội dung trong "..." để mình kiểm tra ngay (ví dụ: "http://scam-prize.com").',
      });
    }

    // 5) Explicit "kiểm tra" → PARSE TAIL AFTER KEYWORD
    if (explicitCheckRequested(userInput)) {
      const tail = tailAfterKeyword(userInput);
      if (tail) {
        const urlInTail = extractFirstUrl(tail);
        if (urlInTail && isBareUrlString(tail)) {
          clearPending(sessionId);
          const prompt = buildPromptCheck(urlInTail, userInput, "url");
          const result = await model.generateContent(prompt);
          return res.json({ output: result.response.text() });
        } else {
          clearPending(sessionId);
          // có thêm chữ sau keyword → coi là mail/toàn bộ đoạn
          const content = tail;
          const prompt = buildPromptCheck(content, userInput, "email");
          const result = await model.generateContent(prompt);
          return res.json({ output: result.response.text() });
        }
      }
      // không có gì sau từ khóa → nhắc dán nội dung
      return res.json({
        output:
          'Bạn muốn kiểm tra gì sau "kiểm tra"? Dán URL trong "..." (ví dụ: "https://chatgpt.com") hoặc paste toàn bộ nội dung để mình kiểm tra.',
      });
    }

    // 6) If message has URL + extra text => disambiguate and store pending
    const { url, more } = hasUrlAndMore(userInput);
    if (url && more) {
      setPending(sessionId, userInput, url);
      const dis = buildPromptAskDisamb(userInput, url);
      return res.json({ output: dis });
    }

    // 7) If only a bare URL => check immediately
    if (url && !more) {
      clearPending(sessionId);
      const prompt = buildPromptCheck(url, userInput, "url");
      const result = await model.generateContent(prompt);
      return res.json({ output: result.response.text() });
    }

    // 8) Default intro ask
    clearPending(sessionId);
    const intro = buildPromptAskIntro();
    return res.json({ output: intro });
  } catch (err) {
    console.error("Assistant error:", err);
    res.status(500).json({ error: err.message || "Assistant error" });
  }
});

module.exports = router;

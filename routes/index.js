// routes/index.js
const express = require("express");
const axios = require("axios");
require("dotenv").config();

const router = express.Router();
router.use(express.json());

const PY_API = process.env.PY_API || "http://localhost:8000";
const API_TOKEN = process.env.API_TOKEN || "";

// in-memory chats: [{id, title, messages:[{role,text,time,result?}]}]
const chats = [];

/* ---------- UI (ChatGPT-like) ---------- */
router.get("/", (_req, res) => {
  res.send(`<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing Chat · AI</title>
<link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <div class="layout">
    <aside class="left">
      <div class="left-top">
        <button id="newChat" class="btn wide primary">+ New chat</button>
        <div class="search">
          <svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79L20 21.49 21.49 20l-5.99-6zM4 9.5C4 6.46 6.46 4 9.5 4S15 6.46 15 9.5 12.54 15 9.5 15 4 12.54 4 9.5z" fill="currentColor"/></svg>
          <input id="search" placeholder="Search chats">
        </div>
      </div>
      <div id="history" class="left-list"></div>
      <div class="left-bottom">
        <div class="me"><span class="tag">Plus</span><span class="name">Bạn</span></div>
      </div>
    </aside>

    <main class="right">
      <header class="topbar">
        <div class="brand">PhishingChat <span class="ver">AI</span></div>
        <div class="actions">
          <a class="btn ghost" href="/ai-health" target="_blank">Health</a>
        </div>
      </header>

      <section id="chat" class="chat">
        <div id="empty" class="empty">Ready when you are.</div>
        <div id="msgs" class="msgs"></div>

        <div class="composer">
          <button id="plus" class="btn ghost">+</button>
          <input id="prompt" class="prompt" placeholder="Ask anything (paste a URL to check)…">
          <div class="tools">
            <button id="mic"  class="btn ghost" title="Mic">🎙️</button>
            <button id="send" class="btn primary" title="Send">➤</button>
          </div>
        </div>
      </section>
    </main>
  </div>

  <div id="toast"></div>
  <script src="/js/scripts.js"></script>
  <script src="/js/index.js"></script>
</body>
</html>`);
});

/* ---------- APIs ---------- */
router.get("/api/chats", (_req, res) => res.json(chats));

router.post("/api/chat", async (req, res) => {
  try {
    const { chatId, text } = req.body || {};
    if (!text) return res.status(400).json({ error: "Missing text" });

    // gọi AI: text là URL -> chuyển thành payload subject/text
    const payload = { subject: "Check URL", text: `url: ${text}` };
    const ai = await axios.post(`${PY_API}/predict`, payload, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${API_TOKEN}`,
      },
      timeout: 15000,
    });

    const data = ai.data || {};
    const classification = data["Email Classification"] || data.class || "";
    const margin = typeof data.margin === "number" ? data.margin : null;
    const isPhishing =
      (classification && classification.toLowerCase() === "spam") ||
      (typeof margin === "number" && margin > 0.5);

    const now = new Date().toISOString();
    const userMsg = { role: "user", text, time: now };
    const aiText = isPhishing
      ? "⚠️ Kết quả: **Phishing**.\n• Phân loại: " +
        classification +
        (margin != null ? ` (margin=${margin})` : "")
      : "✅ Kết quả: **Hợp lệ**.\n• Phân loại: " +
        classification +
        (margin != null ? ` (margin=${margin})` : "");
    const aiMsg = {
      role: "ai",
      text: aiText,
      time: now,
      result: { classification, margin, isPhishing },
    };

    // lưu vào chat
    let chat = chatId ? chats.find((c) => c.id === chatId) : null;
    if (!chat) {
      chat = {
        id: Date.now().toString(),
        title: text.slice(0, 40),
        messages: [],
      };
      chats.unshift(chat);
    }
    chat.title = chat.title || text.slice(0, 40);
    chat.messages.push(userMsg, aiMsg);

    return res.json(chat);
  } catch (err) {
    console.error("AI error:", err?.response?.data || err?.message || err);
    return res.status(502).json({ error: "AI backend error" });
  }
});

// Health proxy
router.get("/ai-health", async (_req, res) => {
  try {
    const r = await axios.get(`${PY_API}/health`, {
      headers: { Authorization: `Bearer ${API_TOKEN}` },
      timeout: 5000,
    });
    res.json({ ok: true, data: r.data });
  } catch (err) {
    res
      .status(502)
      .json({ ok: false, error: err?.message || "Không kết nối AI" });
  }
});

module.exports = router;

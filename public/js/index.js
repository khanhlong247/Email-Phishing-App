// web/public/js/index.js
(async function () {
  const historyEl = document.getElementById("history");
  const msgsEl = document.getElementById("msgs");
  const emptyEl = document.getElementById("empty");
  const prompt = document.getElementById("prompt");
  const send = document.getElementById("send");
  const newBtn = document.getElementById("newChat");
  const search = document.getElementById("search");

  let chats = [];
  let currentId = null;
  let pendingOriginal = null; // lưu nội dung đang chờ xác nhận

  async function load() {
    try {
      const r = await fetch("/api/chats");
      chats = await r.json();
    } catch {
      chats = [];
    }
    renderHistory();
    openFirstIfAny();
  }

  function renderHistory() {
    const q = (search.value || "").toLowerCase();
    historyEl.replaceChildren();
    chats
      .filter((c) => !q || (c.title || "").toLowerCase().includes(q))
      .forEach((c) => {
        const item = $el(
          "div",
          {
            class: `item${c.id === currentId ? " active" : ""}`,
            onclick: () => open(c.id),
          },
          c.title || "New chat",
          $el("small", null, formatTime(c.messages[0]?.time || Date.now()))
        );
        historyEl.append(item);
      });
  }

  function openFirstIfAny() {
    if (!currentId && chats.length) open(chats[0].id);
  }

  function open(id) {
    currentId = id;
    renderHistory();
    const chat = chats.find((c) => c.id === id);
    if (!chat) return;
    msgsEl.replaceChildren();
    emptyEl.style.display = "none";
    chat.messages.forEach((m) =>
      msgsEl.append($el("div", { class: `msg ${m.role}` }, m.text))
    );
    msgsEl.scrollTop = msgsEl.scrollHeight;
  }

  function pushMessageToLocal(role, text) {
    const now = new Date().toISOString();
    let chat = currentId ? chats.find((c) => c.id === currentId) : null;
    if (!chat) {
      chat = {
        id: Date.now().toString(),
        title: role === "user" ? text.slice(0, 40) : "New chat",
        messages: [],
      };
      chats.unshift(chat);
      currentId = chat.id;
    }
    if (!chat.title && role === "user") chat.title = text.slice(0, 40);
    const msg = { role, text, time: now };
    chat.messages.push(msg);
    if (role === "user") {
      msgsEl.append($el("div", { class: "msg user" }, text));
    } else {
      msgsEl.append($el("div", { class: "msg ai" }, text));
    }
    msgsEl.scrollTop = msgsEl.scrollHeight;
    renderHistory();
  }

  function extractJSON(s) {
    const m = s.match(/\{[\s\S]*\}$/);
    if (!m) return null;
    try {
      return JSON.parse(m[0]);
    } catch {
      return null;
    }
  }

  function renderResultCard(obj) {
    if (!obj) return;
    const badgeText = obj.isPhishing ? "Phishing" : "Hợp lệ";
    const badgeClass = obj.isPhishing ? "danger" : "success";
    const card = $el(
      "div",
      { class: "msg ai" },
      $el(
        "div",
        null,
        `📊 Kết quả: `,
        $el(
          "span",
          { class: `badge ${badgeClass}`, style: "margin-left:6px" },
          badgeText
        )
      ),
      $el(
        "div",
        { style: "margin-top:8px;white-space:pre-wrap" },
        `• Loại: ${obj.type}\n• Tin cậy: ${
          isFinite(obj.confidence) ? obj.confidence : "N/A"
        }%\n• Lý do: ${obj.explanation || "N/A"}`
      )
    );
    msgsEl.append(card);
    msgsEl.scrollTop = msgsEl.scrollHeight;
  }

  async function callAssistant(payload) {
    const r = await fetch("/assistant", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!r.ok) throw new Error("Assistant API error");
    return await r.json();
  }

  async function handleUserSend(text) {
    if (!text) return;
    pushMessageToLocal("user", text);

    // If user answers "có" and we have pendingOriginal -> send with context for check
    const isAffirm = /\b(có|ok|đồng ý|được|yes)\b/i.test(text.trim());
    if (isAffirm && pendingOriginal) {
      try {
        const j = await callAssistant({
          input: text,
          context: { original: pendingOriginal },
        });
        const out = j.output || "";
        // parse result
        const parsed = extractJSON(out);
        const chatPart = parsed ? out.replace(/\{[\s\S]*\}$/, "").trim() : out;
        pushMessageToLocal("ai", chatPart || "");
        renderResultCard(parsed);
      } catch (e) {
        pushMessageToLocal("ai", "⚠️ Lỗi khi gọi assistant.");
      } finally {
        pendingOriginal = null;
      }
      return;
    }

    // Otherwise, call assistant normally
    try {
      const j = await callAssistant({ input: text });
      const out = j.output || "";
      // If assistant asked for confirmation (heuristic) -> show question and set pendingOriginal
      const asksConfirm =
        /kiểm tra|gõ 'có'|muốn mình kiểm tra|có muốn/i.test(out) &&
        !/\{[\s\S]*\}$/.test(out);
      if (asksConfirm) {
        pendingOriginal = text; // original content pending
        pushMessageToLocal("ai", out);
        return;
      }

      // If assistant returned JSON (direct check) -> parse and display
      const parsed = extractJSON(out);
      const chatPart = parsed ? out.replace(/\{[\s\S]*\}$/, "").trim() : out;
      pushMessageToLocal("ai", chatPart || "");
      renderResultCard(parsed);
    } catch (e) {
      pushMessageToLocal("ai", "⚠️ Lỗi khi gọi assistant.");
    }
  }

  // UI events
  newBtn.onclick = () => {
    currentId = null;
    renderHistory();
    msgsEl.replaceChildren();
    emptyEl.style.display = "block";
    prompt.focus();
    pendingOriginal = null;
  };
  send.onclick = () => {
    const t = prompt.value.trim();
    if (!t) return;
    handleUserSend(t);
    prompt.value = "";
  };
  prompt.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      send.click();
    }
  });
  search.addEventListener("input", renderHistory);

  await load();
})();

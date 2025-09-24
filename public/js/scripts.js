// tiny helpers + toast
window.$el = (tag, attrs, ...children) => {
  const el = document.createElement(tag);
  if (attrs)
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
  children
    .flat()
    .forEach((c) =>
      el.append(c instanceof Node ? c : document.createTextNode(c))
    );
  return el;
};
window.toast = (msg, type = "info") => {
  let t = document.getElementById("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    t.style.position = "fixed";
    t.style.right = "16px";
    t.style.bottom = "16px";
    document.body.append(t);
  }
  const el = $el("div", {
    class: "item",
    style: "background:#111827;color:#fff;border-color:#0f172a",
  });
  el.textContent = msg;
  t.append(el);
  setTimeout(() => el.remove(), 2500);
};
window.formatTime = (iso) => {
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
};

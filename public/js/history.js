// history.js – Trang lịch sử
(async function () {
  const root = document.getElementById("history-root");

  const controls = $el(
    "div",
    {
      class: "grid",
      style:
        "grid-template-columns: 1fr auto auto; gap:10px; margin-bottom:10px;",
    },
    $el("input", {
      id: "q",
      class: "input",
      placeholder: "Tìm theo domain/URL...",
    }),
    $el(
      "select",
      { id: "filter", class: "input" },
      $el("option", { value: "all" }, "Tất cả"),
      $el("option", { value: "phishing" }, "Chỉ Phishing"),
      $el("option", { value: "safe" }, "Chỉ Hợp lệ")
    ),
    $el("a", { class: "btn", href: "/" }, "Quay lại")
  );

  const table = $el(
    "table",
    { class: "table" },
    $el(
      "thead",
      null,
      $el(
        "tr",
        null,
        $el("th", null, "#"),
        $el("th", null, "Thời điểm"),
        $el("th", null, "URL"),
        $el("th", null, "Kết quả"),
        $el("th", null, "Độ tin cậy")
      )
    ),
    $el(
      "tbody",
      { id: "tb" },
      $el(
        "tr",
        null,
        $el(
          "td",
          { colspan: "5" },
          $el("div", { class: "skeleton", style: "height:40px" })
        )
      )
    )
  );

  root.append(controls, table);

  let data = [];
  try {
    const res = await fetch("/api/history");
    data = (await res.json()) || [];
  } catch (e) {
    toast("Không tải được lịch sử.", "error");
    console.error(e);
    return;
  }

  const render = () => {
    const q = document.getElementById("q").value.trim().toLowerCase();
    const f = document.getElementById("filter").value;
    const tb = document.getElementById("tb");
    tb.replaceChildren();

    const filtered = data.filter((item) => {
      const okF =
        f === "all"
          ? true
          : f === "phishing"
          ? item.isPhishing
          : !item.isPhishing;
      const okQ = !q ? true : (item.url || "").toLowerCase().includes(q);
      return okF && okQ;
    });

    if (filtered.length === 0) {
      tb.appendChild(
        $el("tr", null, $el("td", { colspan: "5" }, "Không có dữ liệu."))
      );
      return;
    }

    filtered.forEach((item, i) => {
      tb.appendChild(
        $el(
          "tr",
          null,
          $el("td", null, String(i + 1)),
          $el("td", null, formatTime(item.timestamp)),
          $el("td", null, $el("code", null, item.url || "")),
          $el(
            "td",
            null,
            item.isPhishing
              ? $el("span", { class: "badge danger" }, "Phishing")
              : $el("span", { class: "badge success" }, "Hợp lệ")
          ),
          $el(
            "td",
            null,
            isFinite(item.confidence) ? `${item.confidence}%` : "N/A"
          )
        )
      );
    });
  };

  document.getElementById("q").addEventListener("input", render);
  document.getElementById("filter").addEventListener("change", render);
  render();
})();

// 수사보드 캠페인 보드 — 후보를 끌어다 전술 열에 놓고, 노드 오른쪽 점을 끌어 다음 노드로 잇는다.
// 바꿀 때마다 서버(dashboard/campaign.py)에 보내고, 돌아온 상태(JSON)로 보드를 다시 그린다.
// 상태의 원본은 늘 서버다 — 화면에서만 옮겨 두고 저장을 잊는 일이 없게.
(function () {
  var pick = document.getElementById("cp-pick");
  if (pick) pick.addEventListener("change", function () { location.href = pick.value; });

  var stateEl = document.getElementById("cp-state");
  var canvas = document.getElementById("cp-canvas");
  if (!stateEl || !canvas) return;

  var state = JSON.parse(stateEl.textContent);
  var base = JSON.parse(document.getElementById("cp-urls").textContent).base;
  var CSRF = (document.querySelector("meta[name=csrf]") || {}).content || "";
  var svg = document.getElementById("cp-lines");
  var labels = document.getElementById("cp-labels");
  var SVGNS = "http://www.w3.org/2000/svg";

  function post(path, data) {
    var body = new URLSearchParams(data || {});
    body.set("_csrf", CSRF);
    return fetch(base + path, { method: "POST", body: body, credentials: "same-origin",
                                headers: { "Accept": "application/json" } })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) throw new Error(j.error || ("요청이 실패했습니다 (" + r.status + ")"));
          return j;
        });
      })
      .then(function (j) { state = j; render(); })
      .catch(function (e) { alert(e.message); });
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ── 그리기 ────────────────────────────────────────────
  function render() {
    var used = {};
    state.nodes.forEach(function (n) { used[n.tactic] = true; });
    canvas.querySelectorAll(".cp-col").forEach(function (col) {
      col.classList.toggle("used", !!used[col.dataset.tactic]);
      col.querySelector(".cp-drop").innerHTML = "";
    });
    state.nodes.forEach(function (n) {
      var drop = canvas.querySelector('.cp-drop[data-tactic="' + n.tactic + '"]');
      if (drop) drop.appendChild(nodeEl(n));
    });
    drawLines();
  }

  function nodeEl(n) {
    var d = el("div", "cp-node k-" + n.kind);
    d.dataset.id = n.id;
    d.draggable = true;
    var top = el("div", "cp-node-top");
    top.appendChild(el("span", "cp-k", n.kind_label));
    if (n.status) { var st = el("span", "cp-st", n.status); st.dataset.st = n.status; top.appendChild(st); }
    var x = el("button", "cp-x", "×");
    x.type = "button"; x.title = "보드에서 빼기";
    x.addEventListener("click", function () {
      if (confirm("'" + n.title + "' 을 보드에서 뺄까요? 이어진 선도 지워집니다.")) post("/nodes/" + n.id + "/delete");
    });
    top.appendChild(x);
    d.appendChild(top);
    d.appendChild(el("div", "cp-node-title", n.title));
    if (n.sub) d.appendChild(el("div", "sub small cp-loc", n.sub));
    var note = el("div", "small cp-node-note" + (n.note ? "" : " empty"), n.note || "메모·근거 문서 적기");
    note.title = "눌러서 고칩니다";
    note.addEventListener("click", function () {
      var v = prompt("메모나 근거 문서 경로", n.note || "");
      if (v !== null) post("/nodes/" + n.id, { note: v });
    });
    d.appendChild(note);
    var h = el("span", "cp-handle");
    h.title = "끌어서 다음 노드로 잇기";
    h.addEventListener("pointerdown", startLink);
    d.appendChild(h);
    d.addEventListener("dragstart", function (e) {
      if (e.target !== d) return;
      e.dataTransfer.setData("text/plain", JSON.stringify({ move: n.id }));
      e.dataTransfer.effectAllowed = "move";
      document.body.classList.add("cp-dragging");
    });
    d.addEventListener("dragend", endDrag);
    return d;
  }

  function anchor(node, side) {
    var c = canvas.getBoundingClientRect(), r = node.getBoundingClientRect();
    return { x: (side === "out" ? r.right : r.left) - c.left, y: r.top + Math.min(r.height / 2, 28) - c.top };
  }

  function curve(a, b) {
    var dx = Math.max(40, Math.abs(b.x - a.x) / 2);
    return "M" + a.x + " " + a.y + " C" + (a.x + dx) + " " + a.y + " " + (b.x - dx) + " " + b.y + " " + b.x + " " + b.y;
  }

  function drawLines() {
    svg.setAttribute("width", canvas.scrollWidth);
    svg.setAttribute("height", canvas.scrollHeight);
    svg.querySelectorAll("path.cp-edge, path.cp-temp").forEach(function (p) { p.remove(); });
    labels.innerHTML = "";
    state.edges.forEach(function (e) {
      var s = canvas.querySelector('.cp-node[data-id="' + e.src + '"]');
      var t = canvas.querySelector('.cp-node[data-id="' + e.dst + '"]');
      if (!s || !t) return;
      var a = anchor(s, "out"), b = anchor(t, "in");
      var p = document.createElementNS(SVGNS, "path");
      p.setAttribute("class", "cp-edge");
      p.setAttribute("d", curve(a, b));
      p.setAttribute("marker-end", "url(#cp-arrow)");
      svg.appendChild(p);
      var lab = el("div", "cp-label" + (e.label ? "" : " empty"));
      lab.style.left = ((a.x + b.x) / 2) + "px";
      lab.style.top = ((a.y + b.y) / 2) + "px";
      var txt = el("span", "", e.label || "넘긴 것?");
      txt.title = "눌러서 고칩니다";
      txt.addEventListener("click", function () {
        var v = prompt("앞 단계에서 얻어 다음 단계에 넘긴 것 (예: JWT_SECRET, ADMIN 토큰)", e.label || "");
        if (v !== null) post("/edges/" + e.id, { label: v });
      });
      var x = el("button", "cp-x", "×");
      x.type = "button"; x.title = "선 지우기";
      x.addEventListener("click", function () { if (confirm("이 선을 지울까요?")) post("/edges/" + e.id + "/delete"); });
      lab.appendChild(txt); lab.appendChild(x);
      labels.appendChild(lab);
    });
  }

  // ── 끌어다 놓기: 후보 → 열, 노드 → 다른 열 ─────────────────
  function endDrag() {
    document.body.classList.remove("cp-dragging");
    canvas.querySelectorAll(".cp-col.over").forEach(function (c) { c.classList.remove("over"); });
  }

  document.querySelectorAll(".cp-cand[draggable=true]").forEach(function (c) {
    c.addEventListener("dragstart", function (e) {
      var d = c.dataset;
      e.dataTransfer.setData("text/plain", JSON.stringify({
        kind: d.kind, ref: d.ref, tactic: d.tactic, title: d.title, sub: d.sub || "",
        status: d.status || "", note: d.note || "" }));
      e.dataTransfer.effectAllowed = "copy";
      document.body.classList.add("cp-dragging");
      var home = canvas.querySelector('.cp-col[data-tactic="' + d.tactic + '"]');
      if (home) home.classList.add("home");
    });
    c.addEventListener("dragend", function () {
      endDrag();
      canvas.querySelectorAll(".cp-col.home").forEach(function (h) { h.classList.remove("home"); });
    });
  });

  canvas.querySelectorAll(".cp-col").forEach(function (col) {
    col.addEventListener("dragover", function (e) { e.preventDefault(); col.classList.add("over"); });
    col.addEventListener("dragleave", function (e) { if (!col.contains(e.relatedTarget)) col.classList.remove("over"); });
    col.addEventListener("drop", function (e) {
      e.preventDefault();
      endDrag();
      var data;
      try { data = JSON.parse(e.dataTransfer.getData("text/plain")); } catch (err) { return; }
      var tactic = col.dataset.tactic;
      if (data.move) {
        var n = state.nodes.filter(function (x) { return x.id === data.move; })[0];
        if (n && n.tactic !== tactic) post("/nodes/" + data.move, { tactic: tactic });
        return;
      }
      data.tactic = tactic;           // 놓은 열이 우선 — 후보의 전술은 기본값일 뿐이다
      post("/nodes", data);
    });
  });

  // ── 잇기: 노드 오른쪽 점을 끌어 다른 노드 위에서 놓는다 ─────────
  var linking = null;
  function startLink(e) {
    e.preventDefault(); e.stopPropagation();
    var from = e.currentTarget.closest(".cp-node");
    var temp = document.createElementNS(SVGNS, "path");
    temp.setAttribute("class", "cp-temp");
    svg.appendChild(temp);
    linking = { from: from, temp: temp, a: anchor(from, "out") };
    document.body.classList.add("cp-linking");
    document.addEventListener("pointermove", moveLink);
    document.addEventListener("pointerup", endLink, { once: true });
  }
  function moveLink(e) {
    var c = canvas.getBoundingClientRect();
    linking.temp.setAttribute("d", curve(linking.a, { x: e.clientX - c.left, y: e.clientY - c.top }));
  }
  function endLink(e) {
    document.removeEventListener("pointermove", moveLink);
    document.body.classList.remove("cp-linking");
    linking.temp.remove();
    var hit = document.elementFromPoint(e.clientX, e.clientY);
    var to = hit && hit.closest(".cp-node");
    var from = linking.from;
    linking = null;
    if (!to || to === from) return;
    var label = prompt("앞 단계에서 얻어 다음 단계에 넘긴 것 (비워 둬도 됩니다)\n예: JWT_SECRET, ADMIN 토큰, 세션 쿠키", "");
    if (label === null) return;
    post("/edges", { src: from.dataset.id, dst: to.dataset.id, label: label });
  }

  // ── 수동 단계 ─────────────────────────────────────────
  var manual = document.getElementById("cp-manual");
  if (manual) manual.addEventListener("submit", function (e) {
    e.preventDefault();
    var f = new FormData(manual);
    post("/nodes", { kind: "manual", ref: "", tactic: f.get("tactic"), title: f.get("title"),
                     status: f.get("status"), note: f.get("note") || "" })
      .then(function () { manual.reset(); });
  });

  window.addEventListener("resize", drawLines);
  // 탭을 바꾸면 숨어 있던 보드의 크기가 0 이었다가 생긴다 — 그때 다시 긋는다
  window.addEventListener("hashchange", function () { setTimeout(drawLines, 0); });
  document.querySelectorAll(".tabs .tab").forEach(function (t) {
    t.addEventListener("click", function () { setTimeout(drawLines, 0); });
  });
  document.querySelectorAll(".cp-cands details").forEach(function (d) {
    d.addEventListener("toggle", function () { setTimeout(drawLines, 0); });
  });
  render();
})();

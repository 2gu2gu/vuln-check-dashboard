// 후보 목록 — 용도별 탭(단서 · 침투 수단 · 다음 시도 · 직접 추가), 찾기, CVE 거르기.
// 캠페인이 아직 없어도 후보는 둘러볼 수 있어야 하므로 보드 코드와 따로 둔다.
(function () {
  var aside = document.querySelector(".cp-cands");
  if (!aside) return;
  var tabs = aside.querySelectorAll("[data-ctab]");
  var panels = aside.querySelectorAll("[data-cpanel]");
  var q = document.getElementById("cp-q");
  var emptyQ = aside.querySelector(".cp-empty-q");
  var KEY = "cpTab";

  function show(name) {
    tabs.forEach(function (t) { var on = t.dataset.ctab === name; t.classList.toggle("on", on); t.setAttribute("aria-selected", on); });
    panels.forEach(function (p) { p.hidden = p.dataset.cpanel !== name; });
    try { localStorage.setItem(KEY, name); } catch (e) {}
    filter();
  }
  tabs.forEach(function (t) { t.addEventListener("click", function () { show(t.dataset.ctab); }); });

  // CVE 는 많다(Tomcat 10.1.1 만 62개, 9.0 이상만도 19개). 기본은 팀이 다룬 것·실제 악용(KEV)만.
  // data-hot: 2 = 팀·KEV, 1 = CVSS 9.0 이상, 0 = 나머지
  var cveMin = 2;
  aside.querySelectorAll("[data-cvefilter]").forEach(function (b) {
    b.addEventListener("click", function () {
      cveMin = +b.dataset.cvefilter;
      aside.querySelectorAll("[data-cvefilter]").forEach(function (x) { x.classList.toggle("on", x === b); });
      filter();
    });
  });

  function filter() {
    var words = (q && q.value || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
    var panel = aside.querySelector("[data-cpanel]:not([hidden])");
    var shown = 0;
    aside.querySelectorAll(".cp-cand").forEach(function (c) {
      var text = c.textContent.toLowerCase();
      var hit = words.every(function (w) { return text.indexOf(w) >= 0; });
      // 찾는 말이 있으면 거르기보다 찾기가 우선 — 숨은 CVE 도 나온다
      var cveHidden = !words.length && c.dataset.hot != null && +c.dataset.hot < cveMin;
      c.hidden = !hit || cveHidden;
      if (!c.hidden && panel && panel.contains(c)) shown++;
    });
    aside.querySelectorAll(".cp-cves").forEach(function (d) {
      var all = d.querySelectorAll(".cp-cand").length;
      var vis = d.querySelectorAll(".cp-cand:not([hidden])").length;
      var note = d.querySelector(".cp-hidden-note");
      if (note) note.textContent = vis < all ? (all - vis) + "개는 접어 두었습니다 — 위 단추로 넓히거나 찾기에 적으세요" : "";
    });
    if (emptyQ) emptyQ.hidden = !(words.length && panel && panel.dataset.cpanel !== "manual" && !shown);
  }
  if (q) q.addEventListener("input", filter);

  // 자주 쓰는 수동 단계 — 누르면 칸을 채운다(바로 올리지는 않는다: 근거 문서를 적게)
  var manual = document.getElementById("cp-manual");
  aside.querySelectorAll(".cp-preset").forEach(function (b) {
    b.addEventListener("click", function () {
      if (!manual) return;
      manual.title.value = b.dataset.title;
      manual.tactic.value = b.dataset.tactic;
      manual.note.focus();
    });
  });

  var start = "clue";
  try { start = localStorage.getItem(KEY) || start; } catch (e) {}
  if (!aside.querySelector('[data-ctab="' + start + '"]')) start = "clue";
  show(start);
})();

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

  // ── 자유 배치(11-22) ──────────────────────────────────
  // 카드는 칸에 갇히지 않는다. 자기 자리(x·y)를 들고 보드 위 아무 데나 놓인다.
  // 전술은 배경 띠로 남는다 — 어느 띠 위에 놓였는지로 전술이 정해진다(서버 campaign.tactic_at 와 같은 셈).
  var LANE_W = 360, CARD_W = 220, TOP = 54, PAD = 90;   // 띠 폭은 campaign.py 의 LANE_W 와 같아야 한다
  var bands = document.getElementById("cp-bands");
  var zoomer = document.getElementById("cp-zoomer");
  var lanes = [].map.call(bands ? bands.children : [], function (b) { return b.dataset.tactic; });
  var Z = 1;
  try { Z = parseFloat(localStorage.getItem("cpZoom")) || 1; } catch (e) { Z = 1; }

  // ── 미니맵 ────────────────────────────────────────────
  // 보드가 가로로 길어 지금 어디를 보고 있는지 모르겠다(11-22 참고 화면). 카드를 작은 네모로
  // 다시 그리고, 지금 보이는 자리를 테두리로 얹는다. 누르면 그 자리로 간다.
  var map = document.getElementById("cp-map");
  var mapView = document.getElementById("cp-map-view");
  var COLOR = { goal: "--sev-critical", cve: "--hit", finding: "--sev-low", observed: "--accent" };

  function drawMap() {
    if (!map) return;
    map.querySelectorAll("i").forEach(function (e) { e.remove(); });
    var w = canvas.offsetWidth || 1, h = canvas.offsetHeight || 1;
    var sx = map.clientWidth / w, sy = map.clientHeight / h;
    state.nodes.forEach(function (n) {
      var b = document.createElement("i");
      b.style.left = (n.x * sx) + "px";
      b.style.top = (n.y * sy) + "px";
      b.style.width = Math.max(3, 220 * sx) + "px";
      b.style.height = Math.max(3, 110 * sy) + "px";
      b.style.background = "var(" + (COLOR[n.kind] || "--line") + ")";
      b.style.opacity = ".75";
      map.appendChild(b);
    });
    mapWhere();
  }

  function mapWhere() {
    if (!mapView || !map) return;
    var box = canvas.parentElement.parentElement;          // 가로로 미는 상자
    var w = canvas.offsetWidth || 1, h = canvas.offsetHeight || 1;
    var sx = map.clientWidth / w, sy = map.clientHeight / h;
    mapView.style.left = (box.scrollLeft / Z * sx) + "px";
    mapView.style.top = (box.scrollTop / Z * sy) + "px";
    mapView.style.width = Math.min(map.clientWidth, box.clientWidth / Z * sx) + "px";
    mapView.style.height = Math.min(map.clientHeight, box.clientHeight / Z * sy) + "px";
  }

  if (map) map.addEventListener("click", function (e) {
    var r = map.getBoundingClientRect();
    var box = canvas.parentElement.parentElement;
    box.scrollLeft = ((e.clientX - r.left) / map.clientWidth) * canvas.offsetWidth * Z - box.clientWidth / 2;
    box.scrollTop = ((e.clientY - r.top) / map.clientHeight) * canvas.offsetHeight * Z - box.clientHeight / 2;
  });

  function laneAt(x) {
    var i = Math.max(0, Math.min(lanes.length - 1, Math.floor((x + CARD_W / 2) / LANE_W)));
    return lanes[i];
  }

  // ── 빈 띠 접기(11-22 사용자: 안 쓰는 칸 때문에 공간이 너무 뜬다) ─────────
  // 자리(x)는 **원래 띠 번호 그대로** 저장해 두고, 화면에만 쓰는 띠를 당겨 붙여 그린다.
  // 펴면 그대로 돌아온다 — 저장된 값을 건드리지 않는다.
  var FOLD = true;
  try { FOLD = localStorage.getItem("cpFold") !== "0"; } catch (e) {}
  var slot = {};                       // 원래 띠 번호 → 화면에서 몇 번째

  function reslot() {
    var used = {};
    state.nodes.forEach(function (n) { used[n.tactic] = true; });
    slot = {};
    var at = 0;
    lanes.forEach(function (t, i) {
      if (!FOLD || used[t]) slot[i] = at++;
    });
    return at || 1;
  }

  function seat(x) {                   // 저장된 x → 화면 x
    var i = Math.max(0, Math.min(lanes.length - 1, Math.floor(x / LANE_W)));
    var s = slot[i];
    if (s === undefined) s = 0;        // 접힌 띠에 있던 카드는 첫 칸에 보인다
    return s * LANE_W + (x - i * LANE_W);
  }

  function unseat(dx) {                // 화면 x → 저장할 x
    var s = Math.max(0, Math.floor(dx / LANE_W));
    var i = 0;
    for (var k in slot) {
      if (slot[k] === s) { i = +k; break; }
    }
    return i * LANE_W + (dx - s * LANE_W);
  }

  function zoom(to) {
    Z = Math.max(0.4, Math.min(1.6, Math.round(to * 20) / 20));
    canvas.style.transform = "scale(" + Z + ")";
    canvas.style.transformOrigin = "0 0";
    if (zoomer) {
      zoomer.style.width = (canvas.offsetWidth * Z) + "px";
      zoomer.style.height = (canvas.offsetHeight * Z) + "px";
    }
    var at = document.getElementById("cp-zoom-at");
    if (at) at.textContent = Math.round(Z * 100) + "%";
    try { localStorage.setItem("cpZoom", Z); } catch (e) {}
    mapWhere();
  }

  // ── 그리기 ────────────────────────────────────────────
  function render() {
    var used = {};
    state.nodes.forEach(function (n) { used[n.tactic] = true; });
    var wide = reslot();                       // 접기까지 셈한 띠 수
    if (bands) [].forEach.call(bands.children, function (b, i) {
      b.classList.toggle("used", !!used[b.dataset.tactic]);
      b.style.display = (slot[i] === undefined) ? "none" : "";
    });
    canvas.querySelectorAll(".cp-node").forEach(function (d) { d.remove(); });
    var far = 0;
    state.nodes.forEach(function (n) {
      var d = nodeEl(n);
      d.style.left = seat(n.x) + "px";
      d.style.top = n.y + "px";
      canvas.appendChild(d);
      far = Math.max(far, n.y + 150);
    });
    canvas.style.width = (wide * LANE_W) + "px";
    canvas.style.height = Math.max(420, far + PAD) + "px";
    zoom(Z);
    drawMap();
    // 이미 올린 후보는 흐리게 — 같은 것을 또 찾지 않게
    var on = {};
    state.nodes.forEach(function (n) { on[n.kind + "|" + n.ref] = true; });
    document.querySelectorAll(".cp-cand[data-kind]").forEach(function (c) {
      c.classList.toggle("on-board", !!on[c.dataset.kind + "|" + c.dataset.ref]);
    });
    drawLines();
  }

  function nodeEl(n) {
    var d = el("div", "cp-node k-" + n.kind);
    d.dataset.id = n.id;
    d.dataset.tactic = n.tactic;
    d.addEventListener("pointerdown", startMove);      // 끌어서 아무 데나 — HTML5 끌어놓기는 확대·축소와 안 맞는다
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
    return d;
  }

  // ── 카드 옮기기 ───────────────────────────────────────
  // 놓은 자리와 **그 자리의 전술**을 같이 저장한다. 끌어다 놓는 것이 곧 전술을 정하는 일이다.
  var moving = null;
  function startMove(e) {
    if (e.button !== 0) return;
    if (e.target.closest(".cp-handle, .cp-x, .cp-node-note")) return;   // 잇기·지우기·메모는 그대로
    var d = e.currentTarget;
    var n = state.nodes.filter(function (x) { return String(x.id) === d.dataset.id; })[0];
    if (!n) return;
    e.preventDefault();
    // 보드 왼쪽 위를 기준으로 센다 — 화면 좌표 그대로 쓰면 보드가 스크롤된 만큼 어긋난다
    var c = canvas.getBoundingClientRect();
    moving = { d: d, n: n, dx: (e.clientX - c.left) / Z - seat(n.x), dy: (e.clientY - c.top) / Z - n.y,
               dirty: false, seen: seat(n.x) };
    d.classList.add("moving");
    document.body.classList.add("cp-moving");
    try { d.setPointerCapture(e.pointerId); } catch (err) {}
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", endMove, { once: true });
  }
  function onMove(e) {
    if (!moving) return;
    var c = canvas.getBoundingClientRect();
    var x = Math.max(0, (e.clientX - c.left) / Z - moving.dx);   // 화면 자리
    var y = Math.max(0, (e.clientY - c.top) / Z - moving.dy);
    moving.seen = x;
    moving.n.x = unseat(x);                                      // 저장은 원래 띠 자리로
    moving.n.y = y; moving.dirty = true;
    moving.d.style.left = x + "px";
    moving.d.style.top = y + "px";
    drawLines();
  }
  function endMove() {
    document.removeEventListener("pointermove", onMove);
    if (!moving) return;
    var m = moving;
    moving = null;
    m.d.classList.remove("moving");
    document.body.classList.remove("cp-moving");
    if (!m.dirty) return;
    var tactic = laneAt(m.n.x);
    m.n.tactic = tactic;
    post("/nodes/" + m.n.id, { x: Math.round(m.n.x), y: Math.round(m.n.y), tactic: tactic });
  }

  // ── 선 긋기 ────────────────────────────────────────────
  // 같은 열 안에서 이으면 오른쪽으로 나갔다 왼쪽으로 돌아오느라 카드 위를 가로질렀다
  // (11-22 사용자 지적: 선이 꼬이고 겹친다). 그래서 어디로 가는지에 따라 길을 가른다.
  //   같은 열    아래 → 위로 곧장 내려 긋는다
  //   다음 열    오른쪽 → 왼쪽, 지금까지처럼 완만한 곡선
  //   뒤로 가기  오른쪽으로 나가 **열 아래 빈 자리**를 돌아 왼쪽으로 들어간다
  function anchor(node, side) {
    // 화면 좌표는 확대·축소가 곱해져 있다 — 보드 좌표로 되돌려 쓴다(Z 로 나눈다)
    var c = canvas.getBoundingClientRect(), r = node.getBoundingClientRect();
    var left = (r.left - c.left) / Z, top = (r.top - c.top) / Z;
    var w = r.width / Z, h = r.height / Z;
    if (side === "down") return { x: left + w / 2, y: top + h };
    if (side === "up") return { x: left + w / 2, y: top };
    return { x: side === "out" ? left + w : left, y: top + Math.min(h / 2, 28) };
  }

  function curve(a, b) {
    var dx = Math.max(40, Math.abs(b.x - a.x) / 2);
    return "M" + a.x + " " + a.y + " C" + (a.x + dx) + " " + a.y + " " + (b.x - dx) + " " + b.y + " " + b.x + " " + b.y;
  }

  function down(a, b) {
    var dy = Math.max(16, (b.y - a.y) / 2);
    return "M" + a.x + " " + a.y + " C" + a.x + " " + (a.y + dy) + " " + b.x + " " + (b.y - dy) + " " + b.x + " " + b.y;
  }

  function around(a, b, floor) {
    // 뒤로 가는 선: 보낸 카드 **아래로 내려가** 밑을 따라 되돌아가서 받는 카드 **밑에서 올라간다**.
    // 옆구리로 돌아 들어가면 카드 오른쪽을 지나 왼쪽으로 꺾여 '뒤로 도는' 모양이 된다
    // (11-22 사용자 지적). 아래로만 다니면 어디로 돌아가는지 한눈에 보인다.
    var y = floor + 26, r = 18;
    return "M" + a.x + " " + a.y
         + " C" + a.x + " " + (a.y + r) + " " + a.x + " " + (y - r) + " " + (a.x - r) + " " + y
         + " L" + (b.x + r) + " " + y
         + " C" + b.x + " " + y + " " + b.x + " " + (y - r) + " " + b.x + " " + b.y;
  }

  function wire(s, t) {
    // 자유 배치에서는 '같은 열' 이 아니라 **가까이 겹쳐 있나**로 가른다 — 위아래로 놓였으면 세로로 긋는다
    var a0 = s.getBoundingClientRect(), b0 = t.getBoundingClientRect();
    var sideways = Math.abs((a0.left + a0.right) / 2 - (b0.left + b0.right) / 2);
    if (sideways < a0.width * 0.8) {
      var top = a0.top <= b0.top;
      var a = anchor(top ? s : t, "down"), b = anchor(top ? t : s, "up");
      return { d: down(a, b), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    }
    var p = anchor(s, "out"), q = anchor(t, "in");
    if (q.x >= p.x) return { d: curve(p, q), x: (p.x + q.x) / 2, y: (p.y + q.y) / 2 };
    // 뒤로 가는 선은 아래로 내려가 **두 카드 중 아래쪽 바로 밑**을 따라 되돌아간다
    var c = canvas.getBoundingClientRect();
    var floor = (Math.max(a0.bottom, b0.bottom) - c.top) / Z;
    var down1 = anchor(s, "down"), up2 = anchor(t, "down");
    return { d: around(down1, up2, floor), x: (down1.x + up2.x) / 2, y: floor + 26 };
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
      var w = wire(s, t);
      var p = document.createElementNS(SVGNS, "path");
      p.setAttribute("class", "cp-edge");
      p.setAttribute("d", w.d);
      p.setAttribute("marker-end", "url(#cp-arrow)");
      svg.appendChild(p);
      var lab = el("div", "cp-label" + (e.label ? "" : " empty"));
      lab.style.left = w.x + "px";
      lab.style.top = w.y + "px";
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

  // ── 끄는 동안 가장자리에 가면 보드가 따라 움직인다 ───────────
  // 브라우저의 끌어다 놓기는 가로 스크롤 상자를 스스로 밀어 주지 않는다. 열이 15개라
  // 오른쪽으로 밀어 둔 상태에서 왼쪽 열(정찰)로 돌아갈 수가 없었다.
  // 끄는 동안 브라우저는 마우스가 멈춰 있어도 dragover 를 계속(약 50ms 마다) 보낸다 — 그때마다 한 걸음씩 민다.
  var scroller = canvas.parentElement;
  var EDGE = 70, STEP = 24;
  document.addEventListener("dragover", function (e) {
    if (!document.body.classList.contains("cp-dragging")) return;
    var r = scroller.getBoundingClientRect(), x = e.clientX, y = e.clientY;
    if (y > r.top && y < r.bottom) {
      if (x > r.left - EDGE && x < r.left + EDGE && scroller.scrollLeft > 0) scroller.scrollLeft -= STEP;
      else if (x > r.right - EDGE && x < r.right + EDGE) scroller.scrollLeft += STEP;
    }
    if (y < 60) window.scrollBy(0, -STEP);
    else if (y > window.innerHeight - 60) window.scrollBy(0, STEP);
  });
  scroller.addEventListener("scroll", function () { drawLines(); mapWhere(); });

  // ── 끌어다 놓기: 후보 → 열, 노드 → 다른 열 ─────────────────
  function endDrag() {
    document.body.classList.remove("cp-dragging");
    canvas.classList.remove("over");
  }

  document.querySelectorAll(".cp-cand[draggable=true]").forEach(function (c) {
    c.addEventListener("dragstart", function (e) {
      var d = c.dataset;
      e.dataTransfer.setData("text/plain", JSON.stringify({
        kind: d.kind, ref: d.ref, tactic: d.tactic, title: d.title, sub: d.sub || "",
        status: d.status || "", note: d.note || "" }));
      e.dataTransfer.effectAllowed = "copy";
      document.body.classList.add("cp-dragging");
      // 그 후보가 기본으로 속한 전술 띠를 밝혀 둔다 — 어디에 놓으면 되는지 보이게
      var home = bands && bands.querySelector('.cp-band[data-tactic="' + d.tactic + '"]');
      if (home) home.classList.add("home");
    });
    c.addEventListener("dragend", function () {
      endDrag();
      if (bands) bands.querySelectorAll(".cp-band.home").forEach(function (h) { h.classList.remove("home"); });
    });
  });

  // 후보를 보드 위 아무 데나 떨어뜨린다 — 떨어진 자리가 곧 자리이고, 그 자리의 띠가 전술이다
  canvas.addEventListener("dragover", function (e) { e.preventDefault(); canvas.classList.add("over"); });
  canvas.addEventListener("dragleave", function (e) {
    if (!canvas.contains(e.relatedTarget)) canvas.classList.remove("over");
  });
  canvas.addEventListener("drop", function (e) {
    e.preventDefault();
    endDrag();
    canvas.classList.remove("over");
    var data;
    try { data = JSON.parse(e.dataTransfer.getData("text/plain")); } catch (err) { return; }
    var c = canvas.getBoundingClientRect();
    var x = unseat(Math.max(0, Math.round((e.clientX - c.left) / Z - CARD_W / 2)));
    var y = Math.max(TOP, Math.round((e.clientY - c.top) / Z - 20));
    data.tactic = laneAt(x);          // 놓은 자리가 우선 — 후보의 전술은 기본값일 뿐이다
    data.x = x; data.y = y;
    post("/nodes", data);
  });

  // ── 정렬 · 확대 축소 ──────────────────────────────────
  var arrangeBtn = document.getElementById("cp-arrange");
  if (arrangeBtn) arrangeBtn.addEventListener("click", function () { post("/arrange"); });
  var foldBtn = document.getElementById("cp-fold");
  function foldLabel() {
    if (foldBtn) foldBtn.textContent = FOLD ? "빈 띠 펴기" : "빈 띠 접기";
  }
  if (foldBtn) foldBtn.addEventListener("click", function () {
    FOLD = !FOLD;
    try { localStorage.setItem("cpFold", FOLD ? "1" : "0"); } catch (e) {}
    foldLabel();
    render();
  });
  foldLabel();
  document.querySelectorAll("[data-zoom]").forEach(function (b) {
    b.addEventListener("click", function () {
      var how = b.dataset.zoom;
      if (how === "in") zoom(Z + 0.1);
      else if (how === "out") zoom(Z - 0.1);
      else {                                   // 전체 보기 — 보드 너비를 창에 맞춘다
        var room = canvas.parentElement.parentElement.clientWidth - 8;
        zoom(room / canvas.offsetWidth);
      }
      drawLines();
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
    linking.temp.setAttribute("d", curve(linking.a, { x: (e.clientX - c.left) / Z, y: (e.clientY - c.top) / Z }));
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

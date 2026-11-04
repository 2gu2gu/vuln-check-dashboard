(function () {
  // 테마: 기본은 밝은 화면. 버튼으로 바꾸면 기억한다(저장 못 해도 동작)
  var root = document.documentElement;
  var btn = document.getElementById("theme");
  if (btn) btn.addEventListener("click", function () {
    var dark = root.dataset.theme === "dark";
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("theme", root.dataset.theme); } catch (e) {}
  });

  // 사전 고르기: 이름으로 좁히기 + 몇 번 나갈지 미리 보기
  // 사람은 경로가 아니라 'raft', 'lfi' 같은 이름 조각으로 기억한다.
  document.querySelectorAll(".wl").forEach(function (box) {
    var find = box.querySelector(".wl-find");
    var pick = box.querySelector(".wl-pick");
    var note = box.querySelector(".wl-note");
    if (!pick) return;

    if (find) find.addEventListener("input", function () {
      var q = find.value.trim().toLowerCase();
      pick.querySelectorAll("optgroup").forEach(function (g) {
        var left = 0;
        g.querySelectorAll("option").forEach(function (o) {
          var hit = !q || o.textContent.toLowerCase().indexOf(q) !== -1
                 || g.label.toLowerCase().indexOf(q) !== -1;
          o.hidden = !hit;
          if (hit) left++;
        });
        g.hidden = left === 0;
      });
      // 고른 것이 가려졌으면 보이는 첫 줄로 옮긴다
      if (pick.selectedOptions[0] && pick.selectedOptions[0].hidden) {
        var first = [].find.call(pick.options, function (o) { return !o.hidden; });
        if (first) { first.selected = true; cost(); }
      }
    });

    function cost() {
      if (!note) return;
      var form = pick.form;
      var limit = form && form.querySelector('[name$="limit"]');
      var n = limit ? parseInt(limit.value, 10) : NaN;
      if (!n || n < 1) { note.textContent = ""; return; }
      var delay = parseInt(document.body.dataset.delayMs, 10) || 0;
      var secs = Math.round(n * delay / 1000);
      var when = secs < 60 ? secs + "초" : Math.round(secs / 60) + "분";
      note.textContent = "요청 " + n.toLocaleString() + "번 · 간격만 따져도 최소 " + when
                       + (n > 2000 ? " — 실행 한도 2,000 에 걸려 중간에 멈춥니다" : "");
      note.classList.toggle("warn-text", n > 2000);
    }
    pick.addEventListener("change", cost);
    var form = pick.form;
    var limit = form && form.querySelector('[name$="limit"]');
    if (limit) limit.addEventListener("input", cost);
    cost();
  });

  // 고르면 바로 적용되는 필터
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form.submit(); });
  });

  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  // 대상 등록: 프로젝트를 고르면 그 프로젝트의 역할만 남긴다
  var proj = document.getElementById("project-pick");
  var rolePick = document.getElementById("role-pick");
  if (proj && rolePick) {
    var sync = function () {
      var first = null;
      [].forEach.call(rolePick.options, function (o) {
        o.hidden = o.dataset.project !== proj.value;
        if (!o.hidden && first === null) first = o;
      });
      if (rolePick.selectedOptions[0] && rolePick.selectedOptions[0].hidden && first) first.selected = true;
    };
    proj.addEventListener("change", sync);
    sync();
  }

  // 요청 기록: 줄 누르면 원문으로
  var hist = document.getElementById("history");
  if (hist) {
    var go = function (e) {
      var tr = e.target.closest("tbody tr");
      if (tr && (e.type === "click" || e.key === "Enter")) location.href = tr.dataset.href;
    };
    hist.addEventListener("click", go);
    hist.addEventListener("keydown", go);
  }
  document.querySelectorAll("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var text = document.getElementById(b.dataset.copy).textContent;
      try { navigator.clipboard.writeText(text); b.textContent = "복사됨"; } catch (e) {}
    });
  });

  // 표면: 전체 선택 · 선택 수 · 모듈별 입력칸
  var probeForm = document.getElementById("probe-form");
  if (probeForm) {
    var boxes = probeForm.querySelectorAll("input[name=point]");
    var picked = document.getElementById("picked");
    var count = function () {
      var n = 0;
      boxes.forEach(function (b) { if (b.checked) n++; });
      picked.textContent = n + "개 선택";
    };
    document.getElementById("pick-all").addEventListener("change", function (e) {
      boxes.forEach(function (b) { b.checked = e.target.checked; });
      count();
    });
    boxes.forEach(function (b) { b.addEventListener("change", count); });
    var sel = document.getElementById("probe-module");
    if (sel) sel.addEventListener("change", function () {
      probeForm.querySelectorAll(".probe-params").forEach(function (d) { d.hidden = d.dataset.for !== sel.value; });
    });
  }

  // 결과 표 → 오른쪽 상세 패널
  var dataEl = document.getElementById("findings-data");
  var table = document.getElementById("findings");
  if (!dataEl || !table) return;
  var byId = {};
  JSON.parse(dataEl.textContent).forEach(function (f) { byId[f.id] = f; });
  var panel = document.getElementById("detail");
  var split = panel.parentElement;
  var $ = function (id) { return document.getElementById(id); };

  function open(tr) {
    var f = byId[tr.dataset.id];
    if (!f) return;
    table.querySelectorAll("tr.sel").forEach(function (r) { r.classList.remove("sel"); });
    tr.classList.add("sel");
    $("d-sev").innerHTML = tr.cells[0].innerHTML;  // 서버가 그린 심각도 배지 재사용
    $("d-title").textContent = f.title;
    $("d-loc").textContent = f.location || "—";
    $("d-mod").textContent = f.module_name;
    $("d-tech").textContent = f.technique || "—";
    $("d-tech").href = f.technique_url || "#";
    $("d-evi").textContent = f.evidence || "—";
    $("d-rec").textContent = f.recommendation || "—";
    var ex = $("d-ex");
    ex.hidden = !f.exchange_id;
    if (f.exchange_id) ex.href = "/history/" + f.exchange_id;
    $("d-status").value = f.status;
    $("d-form").action = "/findings/" + f.id + "/status";
    panel.hidden = false;
    split.classList.add("open");
  }

  table.addEventListener("click", function (e) {
    var tr = e.target.closest("tbody tr");
    if (tr) open(tr);
  });
  table.addEventListener("keydown", function (e) {
    var tr = e.target.closest("tbody tr");
    if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); open(tr); }
  });
  $("d-close").addEventListener("click", function () {
    panel.hidden = true;
    split.classList.remove("open");
    table.querySelectorAll("tr.sel").forEach(function (r) { r.classList.remove("sel"); });
  });

  // 표 안 검색(항목·위치·모듈)
  var q = $("q");
  if (q) q.addEventListener("input", function () {
    var term = q.value.trim().toLowerCase();
    table.querySelectorAll("tbody tr").forEach(function (tr) {
      tr.hidden = term && tr.textContent.toLowerCase().indexOf(term) === -1;
    });
  });
})();

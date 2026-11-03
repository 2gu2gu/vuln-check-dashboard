(function () {
  // 테마: 시스템 설정 → 버튼으로 바꾸면 기억(저장 못 해도 동작)
  var root = document.documentElement;
  var btn = document.getElementById("theme");
  if (btn) btn.addEventListener("click", function () {
    var dark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("theme", root.dataset.theme); } catch (e) {}
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

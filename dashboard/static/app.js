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

  // ── 실행 알림(토스트) ────────────────────────────────────
  // 전에는 화면마다 끝난 작업을 전부 다시 그려서 쌓였다. 이제 한 번만 뜨고
  // 몇 초 뒤 사라진다. 실패는 읽어야 하니 남겨 두고 사람이 닫는다.
  (function () {
    var box = document.getElementById("toasts");
    if (!box) return;
    function drop(el) {
      el.classList.add("leaving");
      setTimeout(function () { el.remove(); }, 250);
    }
    [].forEach.call(box.children, function (el) {
      el.querySelector(".toast-x").addEventListener("click", function () { drop(el); });
      if (!el.dataset.keep) setTimeout(function () { drop(el); }, 6000);
    });
  })();

  // ── 상단 스크롤 진행바 ───────────────────────────────────
  (function () {
    var bar = document.createElement("div");
    bar.className = "scroll-bar";
    document.body.appendChild(bar);
    function draw() {
      var h = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.width = (h > 20 ? (window.scrollY / h) * 100 : 0) + "%";
    }
    window.addEventListener("scroll", draw, {passive: true});
    window.addEventListener("resize", draw);
    draw();
  })();

  // ── 실행하면 아이콘이 '도는 중' 으로 날아간다 ────────────
  // 눌렀는데 화면이 그대로면 아무 일도 안 일어난 줄 안다. 뒤로 갔다는 신호다.
  (function () {
    document.addEventListener("submit", function (e) {
      var form = e.target;
      if (!form.action || form.action.indexOf("/run") === -1) return;
      var card = form.closest(".mod, .tool-form, .probe-bar") || form;
      var dest = document.getElementById("jobs-open");
      if (!dest || !card.getBoundingClientRect) return;
      var a = card.getBoundingClientRect(), b = dest.getBoundingClientRect();
      var fly = document.createElement("div");
      fly.className = "flyer";
      fly.style.left = (a.left + a.width / 2 - 13) + "px";
      fly.style.top = (a.top + 20) + "px";
      document.body.appendChild(fly);
      requestAnimationFrame(function () {
        fly.style.transform = "translate(" + (b.left + b.width / 2 - a.left - a.width / 2) + "px,"
                            + (b.top + b.height / 2 - a.top - 20) + "px) scale(.3)";
        fly.style.opacity = "0";
      });
      setTimeout(function () { fly.remove(); dest.classList.add("bump"); }, 560);
      setTimeout(function () { dest.classList.remove("bump"); }, 950);
    }, true);
  })();

  // ── 모듈 실행 드로어 ─────────────────────────────────────
  // 실행은 뒤에서 돈다. 여기서 진행을 보고, 눌러 들어가면 그 실행이 보낸
  // 요청이 들어오는 대로 쌓인다.
  (function () {
    // $ 는 아래쪽에서 정의되므로 여기서 따로 둔다 (var 는 올라가지만 값은 아직 없다)
    var $ = function (id) { return document.getElementById(id); };
    var drawer = $("jobs-drawer"), openBtn = $("jobs-open");
    if (!drawer || !openBtn) return;
    var list = $("job-list"), detail = $("job-detail"), exBody = $("job-ex");
    var label = $("jobs-label"), spin = $("jobs-spin"), count = $("jobs-count");
    var watching = null, lastEx = 0, timer = null;

    function targetArg() {
      var m = location.search.match(/[?&]target=(\d+)/);
      return m ? "?target=" + m[1] : "";
    }

    function row(j) {
      var li = document.createElement("li");
      li.className = "job" + (j.live ? " job-live" : "");
      li.dataset.run = j.run_id;
      var state = j.live ? "도는 중" :
                  j.status === "done" ? "끝남" :
                  j.status === "cancelled" ? "멈춤" : "실패";
      li.innerHTML =
        '<div class="job-top"><b></b><span class="sub state"></span></div>' +
        '<div class="sub why"></div>' + (j.live ? '<div class="job-bar"><i></i></div>' : "");
      li.querySelector("b").textContent = j.module;
      li.querySelector(".state").textContent = state + " · 요청 " + j.sent + " · " + j.seconds + "초";
      li.querySelector(".why").textContent = j.error || j.message || j.target;
      if (j.live) {
        var stop = document.createElement("button");
        stop.type = "button";
        stop.className = "btn ghost small-btn";
        stop.textContent = "멈춤";
        stop.addEventListener("click", function (e) {
          e.stopPropagation();
          fetch("/jobs/" + j.run_id + "/cancel", {method: "POST"}).then(poll);
        });
        li.querySelector(".job-top").appendChild(stop);
      }
      li.addEventListener("click", function () { watch(j); });
      return li;
    }

    function poll() {
      return fetch("/jobs" + targetArg()).then(function (r) { return r.json(); }).then(function (d) {
        label.textContent = "도는 중 " + d.live;
        spin.hidden = d.live === 0;
        if (count) count.textContent = d.live + " / " + d.max + " 동시 실행";
        list.innerHTML = "";
        if (!d.jobs.length) {
          var li = document.createElement("li");
          li.className = "sub small";
          li.textContent = "아직 돌린 모듈이 없습니다.";
          list.appendChild(li);
        }
        d.jobs.forEach(function (j) { list.appendChild(row(j)); });
        return d;
      }).catch(function () {});
    }

    function pullExchanges() {
      if (!watching) return;
      fetch("/jobs/" + watching + "/exchanges?after=" + lastEx)
        .then(function (r) { return r.json(); })
        .then(function (d) {
          d.exchanges.forEach(function (x) {
            lastEx = Math.max(lastEx, x.id);
            var tr = document.createElement("tr");
            var code = x.error ? "실패" : x.status;
            tr.innerHTML = '<td class="mono"></td><td class="mono"></td><td class="mono"></td>';
            tr.cells[0].textContent = code;
            tr.cells[1].textContent = x.method;
            tr.cells[2].textContent = x.url.replace(/^https?:\/\/[^/]+/, "");
            tr.title = x.error || x.url;
            exBody.appendChild(tr);
          });
          if (d.exchanges.length) exBody.parentNode.scrollTop = exBody.parentNode.scrollHeight;
        }).catch(function () {});
    }

    function watch(j) {
      watching = j.run_id;
      lastEx = 0;
      exBody.innerHTML = "";
      $("job-detail-title").textContent = j.module + " — " + j.target;
      detail.hidden = false;
      pullExchanges();
    }

    $("job-back").addEventListener("click", function () { detail.hidden = true; watching = null; });
    $("jobs-close").addEventListener("click", close);

    function close() {
      drawer.hidden = true;
      openBtn.setAttribute("aria-expanded", "false");
      clearInterval(timer);
      timer = null;
    }

    openBtn.addEventListener("click", function () {
      if (!drawer.hidden) return close();
      drawer.hidden = false;
      openBtn.setAttribute("aria-expanded", "true");
      poll();
      timer = setInterval(function () { poll(); pullExchanges(); }, 900);
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !drawer.hidden) close();
    });

    // 닫혀 있어도 머리의 숫자는 가끔 갱신한다 — 끝난 줄 모르고 기다리지 않게
    poll();
    setInterval(function () { if (drawer.hidden) poll(); }, 4000);
  })();

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
    fillCvss(f.cvss);
    var clear = document.querySelector('[name="cvss"][value="clear"]');
    if (clear) clear.checked = false;
    panel.hidden = false;
    split.classList.add("open");
  }

  // ── CVSS: 고르면 바로 점수를 보여 준다 ─────────────────────
  // 계산식은 서버에만 둔다. JS 로 복사하면 언젠가 둘이 어긋난다.
  function cvssSelects() {
    return [].slice.call(document.querySelectorAll("[data-cvss]"));
  }

  function fillCvss(c) {
    var note = $("d-cvss-note");
    cvssSelects().forEach(function (s) {
      var key = s.dataset.cvss;
      s.value = (c && c.values && c.values[key]) || s.options[0].value;
    });
    if (note) note.textContent = c ? (c.saved ? "" : "모듈이 제안한 값입니다 — 실제에 맞게 고치세요")
                                   : "아직 매기지 않았습니다 — 골라서 저장하세요";
    scoreCvss();
  }

  var scoreTimer = null;
  function scoreCvss() {
    var box = $("d-cvss-score"), vec = $("d-cvss-vector");
    if (!box) return;
    var q = cvssSelects().map(function (s) {
      return s.dataset.cvss + "=" + encodeURIComponent(s.value);
    }).join("&");
    clearTimeout(scoreTimer);
    scoreTimer = setTimeout(function () {
      fetch("/cvss?" + q).then(function (r) { return r.json(); }).then(function (d) {
        if (d.error) { box.textContent = "—"; if (vec) vec.textContent = d.error; return; }
        box.textContent = d.score + " " + d.label;
        box.className = "cvss-score sev-" + d.severity;
        if (vec) vec.textContent = d.vector;
      }).catch(function () { box.textContent = "—"; });
    }, 80);
  }

  document.addEventListener("change", function (e) {
    if (e.target.dataset && e.target.dataset.cvss) scoreCvss();
  });

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

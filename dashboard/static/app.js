(function () {
  // 테마: 기본은 밝은 화면. 버튼으로 바꾸면 기억한다(저장 못 해도 동작)
  var root = document.documentElement;
  var btn = document.getElementById("theme");
  if (btn) btn.addEventListener("click", function () {
    var dark = root.dataset.theme === "dark";
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("theme", root.dataset.theme); } catch (e) {}
  });

  // ── 왼쪽 메뉴 드로어 ─────────────────────────────────────
  // 연 상태를 기억한다 — 화면을 옮길 때마다 다시 열게 하면 성가시다.
  // 좁은 화면에서만 본문을 덮으므로, Esc·뒤 누르기로 닫는 것도 그때만 한다.
  (function () {
    var root = document.documentElement;
    var toggle = document.getElementById("side-toggle");
    var side = document.getElementById("side-nav");
    if (!toggle || !side) return;
    var shut = document.getElementById("side-close");
    var scrim = document.getElementById("side-backdrop");
    var narrow = window.matchMedia("(max-width: 900px)");

    function isOpen() { return root.dataset.side !== "closed"; }
    function sync() { toggle.setAttribute("aria-expanded", isOpen() ? "true" : "false"); }
    function set(open, focusBack) {
      root.dataset.side = open ? "open" : "closed";
      sync();
      try { localStorage.setItem("sideNav", root.dataset.side); } catch (e) {}
      // 열면 머리의 단추가 사라지므로 초점을 안쪽 닫기 단추로 옮긴다 — 안 그러면 초점이 사라진다
      if (open) {
        if (shut) shut.focus();
      } else if (focusBack) {
        toggle.focus();
      }
    }

    sync();
    toggle.addEventListener("click", function () { set(!isOpen(), true); });
    if (shut) shut.addEventListener("click", function () { set(false, true); });
    if (scrim) scrim.addEventListener("click", function () { set(false, false); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && isOpen() && narrow.matches) set(false, true);
    });
  })();

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

  // ── 위에 붙어 있는 머리 높이를 재 둔다 ───────────────────
  // 창이 좁으면 머리가 줄바꿈돼 높이가 달라진다. 고정값을 쓰면 그때 앵커가 어긋난다.
  (function () {
    var head = document.querySelector("header");
    if (!head) return;
    function measure() {
      document.documentElement.style.setProperty("--sticky-h", head.offsetHeight + "px");
    }
    measure();
    window.addEventListener("resize", measure);
    if (window.ResizeObserver) new ResizeObserver(measure).observe(head);
  })();

  // ── #hdr-N 으로 들어오면 그 인증 헤더 칸을 펴 준다 ───────
  // 모듈 카드의 '대상 탭에서 넣기 →' 로 왔는데 표 맨 위에 떨어지고,
  // 칸이 접혀 있어 '없음' 을 눌러야 하는 줄 몰랐다(사용자 지적 11-05).
  (function () {
    function open() {
      var m = /^#hdr-\d+$/.test(location.hash) && document.querySelector(location.hash);
      if (!m) return;
      m.open = true;
      m.classList.add("landed");
      setTimeout(function () { m.scrollIntoView({block: "center"}); }, 0);
      var box = m.querySelector("textarea");
      if (box) setTimeout(function () { box.focus(); }, 200);
      setTimeout(function () { m.classList.remove("landed"); }, 1800);
    }
    open();
    window.addEventListener("hashchange", open);
  })();

  // ── 모듈 카드 접었다 펴기 ────────────────────────────────
  // 15개가 다 펴져 있으면 화면이 끝없이 길어진다. 어느 것을 펴 뒀는지는 기억한다 —
  // 같은 모듈을 연달아 돌려 보는 일이 흔하기 때문이다.
  (function () {
    var cards = document.querySelectorAll(".mod[data-mod]");
    if (!cards.length) return;
    // 펼친 카드를 기억해 다시 펴던 것은 뺀다(11-20). 자세히는 이제 팝업에서 보는데, 기억된 카드가
    // 펴진 채 뜨면 카드를 눌러도 팝업만 열리고 접히지 않았다(사용자 지적). 남아 있는 기억도 지운다.
    var open = {};
    try { localStorage.removeItem("modOpen"); } catch (e) {}

    function set(card, on, animate) {
      var body = card.querySelector(".mod-body");
      var btn = card.querySelector(".mod-open");
      if (!body || !btn) return;
      card.classList.toggle("open", on);
      btn.setAttribute("aria-expanded", on ? "true" : "false");
      if (on && !animate) body.style.animation = "none";
      body.hidden = !on;
      if (on && !animate) requestAnimationFrame(function () { body.style.animation = ""; });
      open[card.dataset.mod] = on;
    }

    cards.forEach(function (card) {
      var btn = card.querySelector(".mod-open");
      if (btn) btn.addEventListener("click", function () {
        var body = card.querySelector(".mod-body");
        // 어쩌다 펴져 있으면 먼저 접는다 — 펴진 채 남지 않게
        if (body && !body.hidden) { set(card, false, true); return; }
        // 모듈은 팝업으로 연다(11-20). 팝업을 못 여는 경우만 예전처럼 카드를 편다
        if (btn.dataset.panel && window.openModulePanel) { window.openModulePanel(btn.dataset.panel); return; }
        set(card, true, true);
      });
      // 접힌 채로 누른 실행 버튼. 필수 칸이 비어 있으면 브라우저는 숨은 칸이라
      // 아무 말 없이 막는다 — 펴서 그 칸을 보여 준 뒤 알린다.
      var quick = card.querySelector(".mod-quick button[form]");
      if (quick) quick.addEventListener("click", function (e) {
        var form = document.getElementById(quick.getAttribute("form"));
        if (form && !form.checkValidity()) {
          e.preventDefault();
          // 칸을 채우는 자리는 이제 팝업이다 — 카드를 펴지 않고 팝업을 연다
          if (btn && btn.dataset.panel && window.openModulePanel) { window.openModulePanel(btn.dataset.panel); return; }
          set(card, true, true);
          form.reportValidity();
        }
      });
    });
  })();

  // ── 왼쪽 묶음 드로어 접기 ────────────────────────────────
  // 접은 상태를 기억한다 — 매번 다시 접게 하면 성가시다.
  (function () {
    var layout = document.querySelector(".mod-layout");
    var btn = document.getElementById("mod-drawer-toggle");
    if (!layout || !btn) return;
    try {
      if (localStorage.getItem("modDrawer") === "folded") layout.classList.add("folded");
    } catch (e) {}
    function sync() {
      var folded = layout.classList.contains("folded");
      btn.setAttribute("aria-expanded", folded ? "false" : "true");
      try { localStorage.setItem("modDrawer", folded ? "folded" : "open"); } catch (e) {}
    }
    sync();
    btn.addEventListener("click", function () { layout.classList.toggle("folded"); sync(); });
  })();

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
    // 화면을 새로 그리지 않고도 알림을 띄운다(11-20) — 실행 시작·실패, 끝난 작업
    window.showToast = function (kind, title, body, link) {
      var el = document.createElement("div");
      el.className = "toast " + (kind === "error" ? "error" : "ok");
      el.setAttribute("role", "status");
      el.innerHTML = '<span class="toast-dot" aria-hidden="true"></span><div><b></b><div class="toast-body"></div></div>'
                   + '<button class="toast-x" type="button" aria-label="닫기">✕</button>';
      el.querySelector("b").textContent = title;
      el.querySelector(".toast-body").textContent = body || "";
      if (link) {
        var a = document.createElement("a");
        a.href = link.href; a.textContent = link.text;
        var d = document.createElement("div"); d.appendChild(a);
        el.querySelector(".toast-body").after(d);
      }
      el.querySelector(".toast-x").addEventListener("click", function () { drop(el); });
      box.appendChild(el);
      if (kind !== "error") setTimeout(function () { drop(el); }, 6000);
    };
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

  // ── 제출이 '막혔을' 때도 말해 준다 ──────────────────────
  // 브라우저 기본 검증에 걸리면 submit 이벤트가 아예 나지 않는다. 그러면 날아가는
  // 표시도, 기다리는 표시도, 서버 메시지도 없다 — 눌렀는데 아무 일도 안 일어난 것처럼
  // 보인다. 도구 탭의 '자체 환경 확인'은 실행할 때마다 다시 꺼지므로 자주 걸린다.
  // (모듈·표면 탭은 required 가 없어 서버까지 가고 거기서 말해 준다.)
  // invalid 는 버블링하지 않는다 — 캡처로 받아야 document 에서 잡힌다.
  var lastJump = 0;
  document.addEventListener("invalid", function (e) {
    var el = e.target;
    if (!el || !el.form) { return; }
    var holder = el.closest("label") || el.parentNode;
    if (!holder || !holder.appendChild) { return; }

    function clear() {                      // 고치면 지운다
      holder.classList.remove("field-bad");
      if (note.parentNode) { note.parentNode.removeChild(note); }
      el.removeEventListener("change", clear);
      el.removeEventListener("input", clear);
    }

    var note = holder.querySelector(".field-bad-note");
    if (!note) {
      note = document.createElement("span");
      note.className = "field-bad-note warn-text";   // 빨강·굵게는 기존 토큰이 한다
      note.setAttribute("role", "alert");
      holder.appendChild(note);
      el.addEventListener("change", clear);          // 쪽지와 한 생애 — clear 가 둘 다 걷는다
      el.addEventListener("input", clear);
    }
    note.textContent = (el.type === "checkbox")
      ? "여기에 체크해야 실행됩니다"
      : (el.validationMessage || "이 칸을 채워 주세요");
    holder.classList.add("field-bad");

    // 여러 칸이 한꺼번에 걸려도 첫 칸으로만 한 번 옮긴다
    if (Date.now() - lastJump > 700) {
      lastJump = Date.now();
      if (el.scrollIntoView) { el.scrollIntoView({block: "center", behavior: "smooth"}); }
    }
  }, true);

  // 페이지마다 하나, 세션에 묶인 값이다(base.html 머리). 폼이 없는 탭에도 서랍이
  // 있어서 숨은 input 에서 주워 읽을 수가 없다 — meta 가 유일한 출처다.
  var CSRF = (document.querySelector('meta[name=csrf]') || {}).content || "";

  // ── 실행하면 그 모듈이 뭉쳐서 '도는 중' 으로 날아간다 ──────
  // 눌렀는데 화면이 그대로면 아무 일도 안 일어난 줄 안다. 뒤로 갔다는 신호다.
  // 전에는 두 가지 때문에 보이지 않았다(사용자 지적 11-05 "눈에 안 띄어").
  //  (1) 출발점이 카드 맨 위였다. 카드를 펴면 실행 버튼은 한참 아래라, 스크롤을 내린 채
  //      누르면 46px 짜리가 화면 위 안 보이는 곳에서 출발했다.
  //  (2) 실행은 뒤에서 돌고 화면은 곧바로 결과/표면 탭으로 넘어간다. 1.1초짜리가
  //      0.2초 만에 잘렸다.
  // 이제 화면에 보이는 카드 만한 덩어리가 그 자리에서 떠오른다. 서랍에 올라가는
  // 실행이면 다 날아간다 — 모듈·표면(뒤에서 돈다)도, 도구(요청 안에서 돈다)도.
  // 가는 곳이 같으면 가는 모습도 같아야 한다. 다른 것은 **그 다음**뿐이다:
  // 뒤에서 도는 쪽은 화면이 곧바로 넘어가므로 다 날아갈 때까지 넘기기를 미루고,
  // 도구는 응답이 올 때까지 화면이 그대로라 미룰 것이 없다.
  (function () {
    var FLY = 750, WAIT = 820;   // 날아가는 시간 / 화면을 넘기기까지. WAIT > FLY 여야 한다
    var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // 어떻게 끝나는 실행인지는 **템플릿이 말해 준다**. data-autosubmit·data-confirm 과
    // 같은 자리다. 주소 모양으로 되짚으면 틀린다 — 실제로 틀렸었다: stage="tool" 모듈
    // 카드도 /modules/<mid>/run 으로 보내는데 서버는 아무것도 안 돌리고 도구 탭으로
    // 넘긴다(routes.py module_run). 주소만 보면 '뒤에서 돈다' 로 읽혀, 도는 것도 없이
    // 날아갔다. 이제 그 카드에는 data-run 이 없어 아무 일도 안 한다.
    document.addEventListener("submit", function (e) {
      var form = e.target;
      if (e.defaultPrevented) return;
      if (form.dataset.run !== "bg") return;   // 없으면 건드리지 않는다
      // 표면 탭은 폼이 지점 표까지 다 감싼다 — 폼을 카드로 쓰면 화면만 한 덩어리가 된다.
      // 누르는 자리인 안쪽 막대(.probe-bar, sticky 라 늘 보인다)를 집는다.
      var card = form.closest(".mod, .tool-form, .probe-bar")
                 || form.querySelector(".probe-bar") || form;

      if (form.dataset.sending) {
        // 넘기기를 미루는 동안 또 누르면 같은 실행이 두 번 들어간다. 전에는 바로
        // 넘어가서 이 구멍이 없었다 — 미루기로 한 이상 여기서 막아야 한다.
        e.preventDefault();
        return;
      }
      var dest = document.getElementById("jobs-open");
      if (!dest || typeof form.submit !== "function") return;

      // 화면을 넘기지 않고 보낸다(사용자 결정 11-20). 고른 지점·넣은 값·열린 팝업이 그대로 남는다.
      e.preventDefault();
      var go = form.querySelector("button[type=submit]");
      var data = new FormData(form);
      if (e.submitter && e.submitter.name) data.append(e.submitter.name, e.submitter.value);
      form.dataset.sending = "1";
      if (go) { go.disabled = true; }
      var title = (card.querySelector("h3") || card.querySelector("h2") || {}).textContent || "실행";
      fetch(form.action, { method: "POST", body: data, credentials: "same-origin",
                           headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var msgs = (d.messages || []).map(function (m) { return m.message; });
          if (d.ok) {
            if (window.showToast) window.showToast("ok", title.trim() + " — 시작", msgs.join(" ") || "뒤에서 돕니다. 오른쪽 위 '도는 중' 에서 봅니다.");
          } else if (window.showToast) {
            window.showToast("error", title.trim() + " — 못 돌림", msgs.join(" "));
          }
          if (window.pollJobs) window.pollJobs();
        })
        .catch(function () { if (window.showToast) window.showToast("error", "보내지 못했습니다", "서버에 닿지 않았습니다. 다시 눌러 보세요."); })
        .then(function () {
          delete form.dataset.sending;
          if (go) { go.disabled = false; }
        });

      if (still) {                       // 움직임을 줄이는 설정이면 테두리만 잠깐 남긴다
        card.classList.add("sent-still");
        setTimeout(function () { card.classList.remove("sent-still"); }, 1200);
        return;
      }

      // 화면에 보이는 부분에서 출발한다 — 카드가 길어 위아래로 벗어나 있어도
      var r = card.getBoundingClientRect();
      var head = document.querySelector("header.top");
      var lo = head ? head.getBoundingClientRect().bottom + 8 : 8;   // 위에 붙은 머리 밑
      var top = Math.max(r.top, lo);
      var box = {left: r.left, width: r.width, top: top,
                 height: Math.min(r.bottom, window.innerHeight - 8) - top};
      if (box.height < 60 || box.width < 60) {   // 카드가 거의 안 보이면 누른 버튼 자리에서
        var hit = e.submitter || form.querySelector("button[type=submit]") || form;
        var hr = hit.getBoundingClientRect();
        box = {left: hr.left, top: hr.top, width: hr.width, height: hr.height};
      }
      box.height = Math.min(box.height, 320);    // 너무 길면 윗동강만 떠오른다
      // 어느 쪽으로든 화면을 벗어났으면 끌어온다. 밖에서 출발하면 안 보이고,
      // 안 보이면 아무 일도 안 일어난 것과 같다 — 이번 건의 출발점이 바로 그거였다.
      box.top = Math.min(Math.max(box.top, lo), window.innerHeight - 8 - box.height);
      box.left = Math.min(Math.max(box.left, 8), window.innerWidth - 8 - Math.min(box.width, window.innerWidth - 16));

      var ghost = document.createElement("div");
      ghost.className = "flyer";
      ghost.style.left = box.left + "px";
      ghost.style.top = box.top + "px";
      ghost.style.width = box.width + "px";
      ghost.style.height = box.height + "px";
      ghost.style.transitionDuration = FLY + "ms";
      ghost.innerHTML = '<span class="flyer-go">\u25b6</span><span class="flyer-name"></span>';
      ghost.querySelector(".flyer-name").textContent = title.trim();
      document.body.appendChild(ghost);

      // 붙인 자세를 한 번 굳히고(강제 리플로우) 바로 목표 자세를 준다.
      // requestAnimationFrame 한 번만으로는 두 자세가 같은 프레임에 묶일 수 있다.
      void ghost.offsetWidth;
      var b = dest.getBoundingClientRect();
      var s = Math.min(1, 60 / Math.max(box.width, 1));
      ghost.style.transform =
        "translate(" + (b.left + b.width / 2 - box.width * s / 2 - box.left) + "px,"
                     + (b.top + b.height / 2 - box.height * s / 2 - box.top) + "px)" +
        " scale(" + s + ") rotate(10deg)";
      ghost.style.opacity = "0";
      card.classList.add("sent");
      setTimeout(function () { dest.classList.add("bump"); }, FLY - 140);
      setTimeout(function () { ghost.remove(); }, WAIT + 1500);   // 화면이 안 넘어가도 치운다

    }, true);
  })();

  // ── 도구 탭: 보던 도구가 끝나면 결과가 뜨게 새로 고친다 ─────
  (function () {
    var wait = document.querySelector("[data-wait-run]");
    if (!wait) return;
    var run = wait.getAttribute("data-wait-run");
    var m = location.search.match(/[?&]target=(\d+)/);
    var arg = m ? "?target=" + m[1] : "";
    var t = setInterval(function () {
      fetch("/jobs" + arg).then(function (r) { return r.json(); }).then(function (d) {
        var j = (d.jobs || []).filter(function (x) { return String(x.run_id) === run; })[0];
        if (j && j.live) return;
        clearInterval(t);
        var u = new URL(location.href);
        u.searchParams.set("run", run);
        location.replace(u.toString());
      }).catch(function () {});
    }, 2000);
  })();

  // ── 모듈 실행 드로어 ─────────────────────────────────────
  // 실행은 뒤에서 돈다. 여기서 진행을 보고, 눌러 들어가면 그 실행이 보낸
  // 요청이 들어오는 대로 쌓인다.
  (function () {
    // $ 는 아래쪽에서 정의되므로 여기서 따로 둔다 (var 는 올라가지만 값은 아직 없다)
    var $ = function (id) { return document.getElementById(id); };
    var drawer = $("jobs-drawer"), openBtn = $("jobs-open");
    if (!drawer || !openBtn) return;
    var list = $("job-list"), detail = $("job-detail"), term = $("job-term"), caret = null;
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
      if (j.result_url) {                    // 도구는 결과 표를 도구 탭에서 다시 연다
        var go = document.createElement("a");
        go.href = j.result_url;
        go.className = "small";
        go.textContent = "결과 표 보기 →";
        go.addEventListener("click", function (e) { e.stopPropagation(); });
        li.appendChild(go);
      }
      if (j.live) {
        var stop = document.createElement("button");
        stop.type = "button";
        stop.className = "btn ghost small-btn";
        stop.textContent = "멈춤";
        stop.addEventListener("click", function (e) {
          e.stopPropagation();
          // _csrf 를 안 실으면 before_request 가 400 으로 자른다 — 지금껏 아무것도
          // 안 멈추고 있었다(실측: POST /jobs/1/cancel → 400).
          if (!CSRF) { stop.textContent = "토큰 없음"; return; }   // 빈 값을 보내 400 을 자초하지 않는다
          fetch("/jobs/" + j.run_id + "/cancel", {
            method: "POST",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: "_csrf=" + encodeURIComponent(CSRF)
          }).then(function (r) {
            // poll() 이 목록을 통째로 다시 그린다 — 실패했으면 글자가 남게 두고 멈춘다
            if (!r.ok) { stop.textContent = "못 멈춤"; return; }
            return poll();
          });
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
        d.jobs.forEach(freshenRunRow);
        (d.done || []).forEach(function (j) {
          if (!window.showToast) return;
          var bad = j.status === "error";
          window.showToast(bad ? "error" : "ok", j.module + (bad ? " — 실패" : j.status === "cancelled" ? " — 멈춤" : " — 끝"),
                           bad ? j.error : (j.message || ("요청 " + j.sent + "개 · " + j.seconds + "초")),
                           j.result_url ? { href: j.result_url, text: "결과 표 보기 →" } : null);
        });
        if ((d.done || []).length && window.refreshModulePanel) window.refreshModulePanel();
        return d;
      }).catch(function () {});
    }

    // 모듈 탭 '최근 실행' 표는 페이지를 그릴 때 한 번 찍힌다. 도는 동안 요청 수가
    // 1 에 멈춰 있어 안 도는 것처럼 보였다(사용자 지적) — 드로어가 받아 오는 같은 값으로
    // 그 줄의 '요청'·'상태' 칸만 갈아 끼운다. **요청 기록 목록은 건드리지 않는다**:
    // 목록이 저절로 바뀌면 누르려던 줄이 달아난다.
    function freshenRunRow(j) {
      var tr = document.querySelector('tr[data-run="' + j.run_id + '"]');
      if (!tr) { return; }
      var reqs = tr.querySelector(".run-reqs");
      if (reqs) {
        var want = j.sent ? '<a href="' + reqs.dataset.href + '">' + j.sent + "개 보기</a>"
                          : '<span class="sub">0</span>';
        if (reqs.innerHTML !== want) { reqs.innerHTML = want; }
      }
      var st = tr.querySelector(".run-status");
      if (st) {
        var cls = j.status === "error" ? "status st-error" : j.status === "done" ? "status st-fixed" : "status";
        var txt = j.status === "error" ? "실패" : j.status === "done" ? "완료"
                : j.status === "cancelled" ? "멈춤" : "도는 중";
        var want2 = '<span class="' + cls + '">' + txt + "</span>"
                  + (j.error ? '<div class="sub small">' + j.error + "</div>" : "");
        if (st.innerHTML !== want2) { st.innerHTML = want2; }
      }
    }

    // 한 줄 = 보낸 요청 하나. 누르면 그 자리에서 패킷 원문이 펴진다.
    function line(x) {
      var el = document.createElement("div");
      el.className = "term-line";
      el.dataset.xid = x.id;
      var code = x.error ? "ERR" : String(x.status);
      var cls = x.error ? "code-x" : "code-" + code.charAt(0);
      var path = x.url.replace(/^https?:\/\/[^/]+/, "") || "/";
      el.setAttribute("role", "button");
      el.setAttribute("tabindex", "0");
      el.setAttribute("aria-expanded", "false");
      el.title = "\ub20c\ub7ec\uc11c \ud328\ud0b7 \uc6d0\ubb38 \ubcf4\uae30";
      el.innerHTML = '<span class="arrow">\u2192</span> <span class="verb"></span> '
                   + '<span class="path"></span> <span class="code ' + cls + '"></span>'
                   + ' <span class="meta"></span>';
      var s = el.querySelectorAll("span");
      s[1].textContent = x.method;
      s[2].textContent = path;
      s[3].textContent = code;
      s[4].textContent = x.error ? x.error : (x.size + "B \u00b7 " + x.ms + "ms");
      el.addEventListener("click", function () { toggleRaw(el, x.id); });
      el.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleRaw(el, x.id); }
      });
      return el;
    }

    function toggleRaw(el, xid) {
      var open = el.nextElementSibling;
      if (open && open.classList.contains("term-raw")) {
        open.remove();
        el.setAttribute("aria-expanded", "false");
        return;
      }
      el.setAttribute("aria-expanded", "true");
      var box = document.createElement("div");
      box.className = "term-raw";
      box.textContent = "\u2026";
      el.insertAdjacentElement("afterend", box);
      fetch("/jobs/exchange/" + xid).then(function (r) { return r.json(); }).then(function (d) {
        box.textContent = "";
        var req = document.createElement("b"); req.textContent = "\u2500 \ubcf4\ub0b8 \uc694\uccad";
        var rq = document.createTextNode("\n" + (d.request || "(\uc5c6\uc74c)") + "\n");
        var res = document.createElement("b"); res.textContent = "\u2500 \ubc1b\uc740 \uc751\ub2f5";
        var rs = document.createTextNode("\n" + (d.error ? d.error : (d.response || "(\uc5c6\uc74c)")));
        box.append(req, rq, res, rs);
      }).catch(function () { box.textContent = "\ubabb \uc77d\uc5c8\uc2b5\ub2c8\ub2e4"; });
    }

    function pullExchanges() {
      if (!watching || !term) return;
      fetch("/jobs/" + watching + "/exchanges?after=" + lastEx)
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var stick = term.scrollTop + term.clientHeight >= term.scrollHeight - 30;
          d.exchanges.forEach(function (x) {
            lastEx = Math.max(lastEx, x.id);
            term.insertBefore(line(x), caret);
          });
          caret.hidden = !d.live;
          if (d.exchanges.length && stick) term.scrollTop = term.scrollHeight;
        }).catch(function () {});
    }

    function watch(j) {
      watching = j.run_id;
      lastEx = 0;
      term.innerHTML = "";
      caret = document.createElement("div");
      caret.className = "term-cursor";
      caret.textContent = "\u2588";
      caret.hidden = !j.live;
      term.appendChild(caret);
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
    window.pollJobs = poll;   // 실행을 보낸 직후 바로 한 번 묻게
  })();

  // 고르면 바로 적용되는 필터.
  // 전에는 폼을 제출해 쪽을 새로 열었는데, 그러면 보던 자리를 잃고 맨 위로 튄다(11-21 사용자 지적).
  // 결과 줄은 이미 다 화면에 있으니 서버에 다시 다녀올 일이 없다 — 그 자리에서 줄만 숨긴다.
  // 주소는 history.replaceState 로 맞춰 둔다(새로 고침·공유했을 때 같은 화면이 나오게).
  (function () {
    var table = document.getElementById("findings");
    var form = document.querySelector("form.filters");
    if (!table || !form) return;
    var pick = function (n) { var el = form.querySelector("[name=" + n + "]"); return el ? el.value : ""; };
    var search = document.getElementById("q");

    function apply(push) {
      var sev = pick("severity"), mod = pick("module_id"), st = pick("status");
      var term = (search && search.value.trim().toLowerCase()) || "";
      var shown = 0;
      table.querySelectorAll("tbody tr").forEach(function (tr) {
        var out = (sev && tr.dataset.sev !== sev) || (mod && tr.dataset.mod !== mod) ||
                  (st && tr.dataset.status !== st) ||
                  (term && tr.textContent.toLowerCase().indexOf(term) === -1);
        tr.hidden = !!out;
        if (!out) shown++;
      });
      var head = document.querySelector(".list-head");
      if (head) {
        var tag = head.querySelector(".shown-count");
        if (!tag) { tag = document.createElement("span"); tag.className = "sub small shown-count"; head.appendChild(tag); }
        tag.textContent = (sev || mod || st || term) ? "  — " + shown + "건 보임" : "";
      }
      if (push) {
        var q = new URLSearchParams(location.search);
        [["severity", sev], ["module_id", mod], ["status", st]].forEach(function (kv) {
          if (kv[1]) q.set(kv[0], kv[1]); else q.delete(kv[0]);
        });
        history.replaceState(null, "", location.pathname + (q.toString() ? "?" + q : ""));
      }
    }

    form.querySelectorAll("[data-autosubmit]").forEach(function (el) {
      el.addEventListener("change", function () { apply(true); });
    });
    if (search) search.addEventListener("input", function () { apply(false); });

    // 위 요약 표·막대를 눌러도 쪽을 새로 열지 않는다 — 같은 대상일 때만
    document.querySelectorAll("[data-filter-sev]").forEach(function (a) {
      a.addEventListener("click", function (e) {
        var mine = form.querySelector("[name=target]");
        if (!mine || a.dataset.filterTarget !== mine.value) return;   // 다른 대상이면 그냥 이동
        e.preventDefault();
        var sel = form.querySelector("[name=severity]");
        if (sel) sel.value = (sel.value === a.dataset.filterSev) ? "" : a.dataset.filterSev;  // 같은 걸 또 누르면 해제
        apply(true);
      });
    });

    var hasFilter = form.querySelector("[name=severity]").value || form.querySelector("[name=module_id]").value
                    || form.querySelector("[name=status]").value;
    if (hasFilter) apply(false);     // 주소로 들어왔을 때도 표시를 맞춘다
  })();

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
    // 추천 점검 칩: 그 지점을 고르고, 점검 모듈을 추천한 것으로 맞춘 뒤 점검 막대로 간다
    probeForm.querySelectorAll(".sg[data-mod]").forEach(function (chip) {
      chip.addEventListener("click", function () {
        var box = probeForm.querySelector('input[name=point][value="' + chip.dataset.point + '"]');
        if (box) box.checked = true;
        var sel = document.getElementById("probe-module");
        if (sel) { sel.value = chip.dataset.mod; sel.dispatchEvent(new Event("change")); }
        count();
        var bar = probeForm.querySelector(".probe-bar");
        if (bar) bar.scrollIntoView({ behavior: "smooth", block: "center" });
      });
    });
    document.getElementById("pick-all").addEventListener("change", function (e) {
      boxes.forEach(function (b) { if (!b.hidden) b.checked = e.target.checked; });
      count();
    });
    boxes.forEach(function (b) { b.addEventListener("change", count); });
    var sel = document.getElementById("probe-module");
    var hint = document.getElementById("pick-hint");
    // 고른 모듈이 받는 단위에 맞춰 고를 자리를 바꾼다 — 주소 단위(보안 헤더·정보 노출)는 주소 줄,
    // 파라미터 단위는 파라미터 줄. 안 쓰는 쪽은 숨기고 선택도 지운다(0개 선택으로 멈추지 않게).
    var unitSwitch = function () {
      var opt = sel.options[sel.selectedIndex];
      var unit = (opt && opt.dataset.unit) || "param";
      var usable = 0;
      boxes.forEach(function (b) {
        b.hidden = b.dataset.unit !== unit;
        if (b.hidden) { b.checked = false; } else { usable++; }
      });
      if (hint) {
        hint.hidden = usable > 0 && unit === "param";
        hint.textContent = usable === 0
          ? (unit === "param" ? "고를 파라미터가 없습니다 — 표면 수집으로 더 모으거나 HAR 을 붙여 넣으세요"
                              : "고를 주소가 없습니다 — 표면 수집을 먼저 돌리세요")
          : "이 모듈은 주소마다 봅니다 — 주소 줄(굵은 경로)에서 고르세요";
      }
      count();
    };
    if (sel) {
      sel.addEventListener("change", function () {
        probeForm.querySelectorAll(".probe-params").forEach(function (d) { d.hidden = d.dataset.for !== sel.value; });
        unitSwitch();
      });
      unitSwitch();
    }
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

  // 표 안 검색은 위의 거르기(apply)로 합쳤다 — 심각도·모듈·상태와 같이 걸려야 한다
})();


// 글자 찾기 — 받은 응답·보낸 요청·도구 결과 같은 긴 텍스트 상자 안에서 찾는다.
// 브라우저 Ctrl+F 와 달리 대시보드 화면에 남고, 그 상자들만 훑어 몇 번째/몇 개인지 보여 준다.
(function () {
  var pres = [].slice.call(document.querySelectorAll("#raw-req, #raw-resp, pre.tool-text"));
  // CSS Custom Highlight API 가 없는 옛 브라우저에서는 바를 안 띄운다 — Ctrl+F 를 쓰면 된다
  if (!pres.length || !window.CSS || !CSS.highlights || typeof Highlight === "undefined") return;

  var bar = document.createElement("div");
  bar.className = "find-bar";
  bar.innerHTML =
    '<input type="search" class="find-q" placeholder="이 안에서 글자 찾기" aria-label="글자 찾기">' +
    '<span class="find-count sub small" role="status"></span>' +
    '<button type="button" class="btn ghost small-btn find-prev" aria-label="이전 찾은 것">\u2191</button>' +
    '<button type="button" class="btn ghost small-btn find-next" aria-label="다음 찾은 것">\u2193</button>';
  var anchor = pres[0].closest(".exchange, .tool-result") || pres[0];
  anchor.parentNode.insertBefore(bar, anchor);

  var q = bar.querySelector(".find-q"), count = bar.querySelector(".find-count");
  var ranges = [], at = -1;

  function clear() {
    CSS.highlights.delete("find"); CSS.highlights.delete("find-at");
    ranges = []; at = -1; count.textContent = "";
  }

  function run() {
    var term = q.value;
    clear();
    if (!term) return;
    var low = term.toLowerCase(), all = new Highlight();
    pres.forEach(function (pre) {
      var w = document.createTreeWalker(pre, NodeFilter.SHOW_TEXT), n;
      while ((n = w.nextNode())) {
        // shortcut: 한 텍스트 노드 안에서만 찾는다 — <mark>(vcd...) 토큰 경계를 넘는 일치는 못 찾는다. 드물다.
        var t = n.nodeValue.toLowerCase(), i = 0, p;
        while ((p = t.indexOf(low, i)) !== -1) {
          var r = document.createRange();
          r.setStart(n, p); r.setEnd(n, p + term.length);
          ranges.push(r); all.add(r);
          i = p + term.length;
        }
      }
    });
    CSS.highlights.set("find", all);
    count.textContent = ranges.length ? "0/" + ranges.length : "없음";
    if (ranges.length) go(0);
  }

  function go(i) {
    if (!ranges.length) return;
    at = (i + ranges.length) % ranges.length;
    var one = new Highlight(); one.add(ranges[at]);
    CSS.highlights.set("find-at", one);         // 지금 보는 것만 색을 달리한다
    count.textContent = (at + 1) + "/" + ranges.length;
    ranges[at].startContainer.parentElement.scrollIntoView({ block: "center" });
  }

  var timer;
  q.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(run, 120); });
  q.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); go(at + (e.shiftKey ? -1 : 1)); }
  });
  bar.querySelector(".find-next").addEventListener("click", function () { go(at + 1); });
  bar.querySelector(".find-prev").addEventListener("click", function () { go(at - 1); });
})();


// 한 페이지 안의 탭 — 주소의 #이름 으로 고른 칸만 보인다(수사보드 | ATT&CK 매트릭스).
// JS 가 없으면 두 칸이 위아래로 다 보인다. 옛 /attack 주소는 #matrix 로 들어온다.
(function () {
  var tabs = document.querySelectorAll(".tabs .tab");
  if (!tabs.length) return;
  var showTab = function () {
    var want = location.hash.slice(1), names = [];
    tabs.forEach(function (t) { names.push(t.dataset.tab); });
    if (names.indexOf(want) < 0) want = names[0];
    tabs.forEach(function (t) {
      var on = t.dataset.tab === want;
      t.classList.toggle("on", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
      var panel = document.getElementById(t.dataset.tab);
      if (panel) panel.hidden = !on;
    });
  };
  tabs.forEach(function (t) {
    t.addEventListener("click", function (e) {
      e.preventDefault();                       // 탭 머리로 화면이 튀지 않게 주소만 바꾼다
      history.replaceState(null, "", "#" + t.dataset.tab);
      showTab();
    });
  });
  window.addEventListener("hashchange", showTab);
  showTab();
})();

// ── 모듈 팝업(11-20 사용자 결정) ─────────────────────────────
// 모듈을 누르면 왼쪽에 설정·실행, 오른쪽에 이 대상이 모은 지점 표가 뜬다. 지점 점검 모듈은
// 여기서 지점을 골라 바로 돌린다. 실행하면 서버가 '같은 팝업을 다시 연 모듈 화면' 으로 돌려보낸다.
(function () {
  var dlg = document.getElementById("mod-dialog");
  if (!dlg || typeof dlg.showModal !== "function") return;

  function count() {
    var boxes = dlg.querySelectorAll('input[name=point][form="mp-form"]');
    var n = dlg.querySelectorAll('input[name=point][form="mp-form"]:checked').length;
    var c = dlg.querySelector(".mp-count");
    if (c) c.textContent = n;
    // 머리글 '전체 선택'·주소별 선택 칸을 아래 칸들과 맞춘다(일부만 고르면 반쯤 찬 표시)
    function sync(box, list) {
      if (!box) return;
      var on = Array.prototype.filter.call(list, function (b) { return b.checked; }).length;
      box.checked = list.length > 0 && on === list.length;
      box.indeterminate = on > 0 && on < list.length;
    }
    sync(dlg.querySelector(".mp-all"), boxes);
    dlg.querySelectorAll(".mp-group").forEach(function (g) {
      sync(g, g.closest("tbody").querySelectorAll('input[name=point]'));
    });
  }

  var current = "";
  window.openModulePanel = function (url, keep) {
    current = url;
    // 다시 받아 올 때 고른 지점·넣은 값을 지키려고 미리 적어 둔다
    var picked = keep ? Array.prototype.map.call(dlg.querySelectorAll('input[name=point]:checked'), function (b) { return b.value; }) : [];
    var vals = {};
    if (keep) dlg.querySelectorAll("#mp-form input:not([type=hidden]):not([type=checkbox]), #mp-form select, #mp-form textarea, #mp-form input[type=checkbox]")
      .forEach(function (el) { vals[el.name] = el.type === "checkbox" ? el.checked : el.value; });
    var scroll = (dlg.querySelector(".mp-table") || {}).scrollTop || 0;
    fetch(url, { headers: { "X-Requested-With": "fetch" } })
      .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function (html) {
        dlg.innerHTML = html;
        if (keep) {
          dlg.querySelectorAll("input[name=point]").forEach(function (b) { b.checked = picked.indexOf(b.value) >= 0; });
          Object.keys(vals).forEach(function (n) {
            var el = dlg.querySelector('#mp-form [name="' + n + '"]');
            if (!el) return;
            if (el.type === "checkbox") el.checked = vals[n]; else el.value = vals[n];
          });
          var t = dlg.querySelector(".mp-table"); if (t) t.scrollTop = scroll;
        }
        if (!dlg.open) dlg.showModal();
        count();
      })
      .catch(function () { location.href = url.replace(/([?&])partial=1&?/, "$1"); });
  };

  // 실행이 끝나면(드로어가 알려 줌) 열린 팝업의 판정만 새로 받아 온다
  window.refreshModulePanel = function () { if (dlg.open && current) window.openModulePanel(current, true); };

  dlg.addEventListener("click", function (e) {
    if (e.target === dlg || e.target.closest(".mp-close")) { dlg.close(); return; }
    var pick = e.target.closest("[data-pick]");
    if (pick) {
      var how = pick.dataset.pick;
      dlg.querySelectorAll('input[name=point][form="mp-form"]').forEach(function (b) {
        b.checked = how === "all" || (how === "suggest" && b.dataset.suggest === "1");
      });
      count();
    }
  });
  dlg.addEventListener("change", function (e) {
    var t = e.target;
    if (t.classList.contains("mp-all")) {
      dlg.querySelectorAll('input[name=point][form="mp-form"]').forEach(function (b) { b.checked = t.checked; });
    } else if (t.classList.contains("mp-group")) {
      t.closest("tbody").querySelectorAll('input[name=point]').forEach(function (b) { b.checked = t.checked; });
    }
    if (t.name === "point" || t.classList.contains("mp-all") || t.classList.contains("mp-group")) count();
  });
  dlg.addEventListener("submit", function (e) {
    var form = e.target;
    if (form.id === "mp-form" && form.querySelector('input[name=module_id]') &&
        !dlg.querySelector('input[name=point][form="mp-form"]:checked')) {
      e.preventDefault();
      alert("점검할 지점을 고르세요 — 오른쪽 표에서 체크하거나 '추천 지점만' 을 누르세요.");
    }
  }, true);

  // 지점 점검 모듈 카드의 '지점 골라 점검' 단추
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-open-panel]");
    if (!b) return;
    var card = b.closest(".mod");
    var open = card && card.querySelector(".mod-open");
    if (open && open.dataset.panel) window.openModulePanel(open.dataset.panel);
  });

  // ?open=<모듈 id> 로 들어오면(실행 뒤 돌아온 자리) 그 팝업을 바로 연다
  var want = dlg.dataset.open;
  if (want) {
    var c = document.querySelector('.mod[data-mod="' + want + '"] .mod-open');
    if (c && c.dataset.panel) window.openModulePanel(c.dataset.panel);
  }
})();

// ── MCP 탭: 붙었는지 스스로 켜지는 불 ─────────────────────
// 줄을 복사해 터미널에 넣는 사람은 이 화면을 보고 있다. 새로 고치라고 하지 않고
// 몇 초마다 물어봐서 붙는 순간 불이 켜지게 한다(11-21 사용자 지적: 붙었는지 안 보인다).
(function () {
  var box = document.getElementById("mcp-live");
  if (!box) return;
  var head = document.getElementById("mcp-head");
  var sub = document.getElementById("mcp-sub");
  var calls = document.getElementById("mcp-calls");
  var SAY = { live: "붙어 있습니다", idle: "조용합니다", waiting: "아직 아무도 안 붙었습니다" };

  function draw(d) {
    var was = box.dataset.state;
    box.dataset.state = d.state;
    head.textContent = SAY[d.state] || "";
    calls.textContent = d.calls;
    if (d.state === "waiting") {
      sub.innerHTML = "아래 줄을 터미널에 넣으면 <b>여기 불이 켜집니다</b>";
    } else {
      sub.textContent = d.client + " · 마지막 " + d.when + (d.last_tool ? " " + d.last_tool : "");
    }
    // 처음 붙는 순간에만 화면을 한 번 새로 그린다 — 기록 표에도 그 줄이 보이게
    if (was === "waiting" && d.state === "live") setTimeout(function () { location.reload(); }, 1200);
  }

  setInterval(function () {
    fetch("/connect/state").then(function (r) { return r.json(); }).then(draw).catch(function () {});
  }, 3000);
})();

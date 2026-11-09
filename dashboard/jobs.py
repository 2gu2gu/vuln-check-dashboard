"""모듈을 요청 밖에서 돌린다 — 여러 개를 동시에, 진행을 보면서.

전에는 모듈이 HTTP 요청 하나 안에서 끝까지 돌았다. SQL 주입으로 테이블을 읽거나
경로를 400번 때리는 동안 브라우저가 멈춰 있었고, 두 개를 같이 돌릴 수 없었다.

이제 실행은 **시작만** 하고 바로 돌아온다. 작업자 스레드가 뒤에서 돌면서 요청을
보내고, 화면은 진행을 물어본다.

## 안전장치는 그대로다

범위 검사·요청 간격·실행 한도는 요청 컨텍스트(`g`)에 묶여 있었다. 스레드마다
`app.app_context()` 를 새로 열어 그 안에 똑같이 깔아 둔다. 스레드가 달라도
`g` 는 컨텍스트마다 따로라 섞이지 않는다.

**동시에 도는 수에 상한(MAX_LIVE)을 둔다.** 같은 서버를 여러 모듈이 동시에 때리면
요청 간격을 지켜도 합쳐진 양은 그만큼 늘어난다. 공유 서버라 그게 제일 위험하다.

## 취소

도는 중에 멈출 수 있다. 다음 요청을 보내기 직전에 확인하므로, 이미 나간 요청은
돌아올 때까지 기다린다 — 끊어도 서버 쪽에는 이미 닿았기 때문이다.
"""
import threading
import time
import traceback

MAX_LIVE = 4          # 동시에 도는 모듈 수 상한
KEEP = 40             # 끝난 작업을 화면에 남겨 두는 수

_lock = threading.Lock()
_jobs = {}            # run_id -> Job
_order = []           # 끝난 것부터 지우려고 들어온 순서를 센다


class Cancelled(Exception):
    """사람이 멈춤을 눌렀을 때."""


class Job:
    def __init__(self, run_id, target, module):
        self.run_id = run_id
        self.target_id, self.target_name = target["id"], target["name"]
        self.module_id, self.module_name = module.id, module.name
        self.stage = getattr(module, "stage", "")   # 도구면 끝난 뒤 결과 표로 가는 링크를 단다
        self.status = "running"          # running · done · error · cancelled
        self.message = ""
        self.error = ""
        self.started = time.time()
        self.finished = None
        self.ctx = None                  # RunContext — 보낸 요청 수를 여기서 읽는다
        self.announced = False           # 끝났다고 화면에 한 번 알렸는지
        self._stop = threading.Event()

    # ── 화면이 보는 것 ────────────────────────────────────────
    @property
    def sent(self):
        return getattr(self.ctx, "count", 0)

    @property
    def seconds(self):
        return round((self.finished or time.time()) - self.started, 1)

    @property
    def live(self):
        return self.status == "running"

    def as_dict(self):
        return {"run_id": self.run_id, "target_id": self.target_id, "target": self.target_name,
                "module_id": self.module_id, "module": self.module_name, "stage": self.stage, "status": self.status,
                "sent": self.sent, "seconds": self.seconds, "message": self.message,
                "error": self.error, "live": self.live}

    # ── 취소 ──────────────────────────────────────────────────
    def cancel(self):
        self._stop.set()

    def should_stop(self):
        if self._stop.is_set():
            raise Cancelled("사람이 멈췄습니다")


def live_count():
    with _lock:
        return sum(1 for j in _jobs.values() if j.live)


def get(run_id):
    with _lock:
        return _jobs.get(run_id)


def listing(target_id=None):
    """드로어에 뿌릴 목록. 도는 것이 위, 그 아래 최근 끝난 것."""
    with _lock:
        rows = [j for j in _jobs.values() if target_id is None or j.target_id == target_id]
    rows.sort(key=lambda j: (not j.live, -j.started))
    return [j.as_dict() for j in rows]


def take_announcements(target_id=None):
    """끝난 작업 중 **아직 안 알린 것**만. 한 번 가져가면 다시 안 준다.

    전에는 화면을 그릴 때마다 끝난 작업을 전부 다시 그려서, 새로고침할수록
    알림이 쌓여 화면을 가렸다. 알림은 한 번이면 된다 — 기록은 드로어에 남는다.
    """
    out = []
    with _lock:
        for j in _jobs.values():
            if j.live or j.announced:
                continue
            if target_id is not None and j.target_id != target_id:
                continue
            j.announced = True
            out.append(j)
    out.sort(key=lambda j: j.finished or 0)
    return [j.as_dict() for j in out]


def cancel(run_id):
    job = get(run_id)
    if job and job.live:
        job.cancel()
        return True
    return False


def _remember(job):
    with _lock:
        _jobs[job.run_id] = job
        _order.append(job.run_id)
        # 끝난 것부터 오래된 순으로 지운다. 도는 것은 절대 지우지 않는다
        while len(_order) > KEEP:
            for i, rid in enumerate(_order):
                old = _jobs.get(rid)
                if old is None or not old.live:
                    _order.pop(i)
                    _jobs.pop(rid, None)
                    break
            else:
                break


def start(app, run_id, target, module, work):
    """작업자 스레드를 띄운다.

    work(job) 는 app_context 안에서 불린다. 그 안에서 g.* 를 깔고 모듈을 돌린 뒤
    (상태, 메시지) 를 돌려준다. 여기서는 스레드·상한·예외만 맡는다.
    """
    job = Job(run_id, target, module)
    _remember(job)

    def body():
        with app.app_context():
            try:
                job.message = work(job) or ""
                job.status = "done" if not job._stop.is_set() else "cancelled"
            except Cancelled as e:
                job.status, job.error = "cancelled", str(e)
            except Exception as e:  # noqa: BLE001 — 실패도 기록으로 남긴다
                job.status, job.error = "error", str(e)
                app.logger.warning("모듈 실행 실패 %s: %s\n%s", module.id, e, traceback.format_exc())
            finally:
                job.finished = time.time()

    t = threading.Thread(target=body, name=f"run-{run_id}-{module.id}", daemon=True)
    job.thread = t
    t.start()
    return job


def wait_all(timeout=10):
    """테스트용 — 도는 작업이 끝날 때까지 기다린다."""
    end = time.time() + timeout
    while time.time() < end:
        with _lock:
            threads = [j.thread for j in _jobs.values() if j.live and getattr(j, "thread", None)]
        if not threads:
            return True
        for t in threads:
            t.join(timeout=0.05)
    return False


def reset():
    """테스트용 — 기록을 비운다."""
    with _lock:
        _jobs.clear()
        _order.clear()

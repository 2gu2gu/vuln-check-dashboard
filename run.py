"""로컬 실행: python run.py → http://127.0.0.1:5050 (포트는 DASH_PORT 로 바꾼다)"""
import os

from dashboard import create_app

if __name__ == "__main__":
    app = create_app()
    # 점검 도구라 기본은 루프백에만 연다 — 앞에 nginx 를 두는 서버 배치에서도 이게 맞다.
    # nginx 없이 바로 열어야 하면 DASH_BIND=0.0.0.0.
    # SELF_PORT 와 같은 포트여야 자기 점검 차단이 맞는다
    app.run(host=os.environ.get("DASH_BIND", "127.0.0.1"), port=app.config["SELF_PORT"],
            debug=False, threaded=True)

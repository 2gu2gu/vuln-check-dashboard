"""로컬 실행: python run.py → http://127.0.0.1:5050 (포트는 DASH_PORT 로 바꾼다)"""
from dashboard import create_app

if __name__ == "__main__":
    app = create_app()
    # 점검 도구라 외부에서 접속하지 못하게 루프백에만 연다. SELF_PORT 와 같은 포트여야 자기 점검 차단이 맞는다
    app.run(host="127.0.0.1", port=app.config["SELF_PORT"], debug=False, threaded=True)

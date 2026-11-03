"""로컬 실행: python run.py → http://127.0.0.1:5050"""
from dashboard import create_app

if __name__ == "__main__":
    # 점검 도구라 외부에서 접속하지 못하게 루프백에만 연다
    create_app().run(host="127.0.0.1", port=5050, debug=False)

### FuzzLab

백엔드 파이프라인 연동 & Open-webUI 연결은 아래 명령어 참고하시면 됩니다.

- Terminal 1: `uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000`
- Terminal 2: `celery -A backend.app.celery_app.celery_app worker --loglevel=INFO`
- Terminal 3: `ollama serve`
- Terminal 4: `docker run -d \
  --name open-webui \
  --network host \
  -e OLLAMA_BASE_URL=http://127.0.0.1:11434 \
  -v open-webui:/app/backend/data \
  --restart unless-stopped \
  ghcr.io/open-webui/open-webui:main

`
접속은 http://localhost:8080

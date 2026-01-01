from celery import Celery

# docker-compose -> redis가 기본 포트 6379로 열려있는 상황
celery_app = Celery(
    "fuzzlab",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Seoul",
    enable_utc=True,
)

#celery에서 tasks 모듈 확실히 import하기 위해 추가함
celery_app.autodiscover_tasks(["backend.app"])
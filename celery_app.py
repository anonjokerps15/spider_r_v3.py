from celery import Celery

celery = Celery('spider_r', broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

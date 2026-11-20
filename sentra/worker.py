import os
from celery import Celery
from detector import classify
from service import run_scan

app = Celery('sentra', broker=os.environ['BROKER_URL'], backend=os.environ['REDIS_URL'])
app.conf.update(result_expires=300, broker_connection_retry_on_startup=True, task_serializer='json',
                accept_content=['json'], task_publish_retry=False, broker_connection_timeout=5)


@app.task
def analyze_job(kind, features):
    return classify(kind, features)


@app.task(acks_late=True, reject_on_worker_lost=True)
def process_scan(scan_id):
    return run_scan(scan_id)

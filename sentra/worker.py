import json
import os
from celery import Celery
from confluent_kafka import Producer
from detector import classify

app = Celery('sentra', broker=os.environ['BROKER_URL'], backend=os.environ['REDIS_URL'])
app.conf.update(result_expires=300, broker_connection_retry_on_startup=True, task_serializer='json',
                accept_content=['json'], task_publish_retry=False, broker_connection_timeout=5)


@app.task
def analyze_job(kind, features):
    return classify(kind, features)


@app.task(autoretry_for=(RuntimeError,), retry_backoff=True, max_retries=5, ignore_result=True)
def emit_event(scan_id, kind, level):
    producer = Producer({'bootstrap.servers': 'kafka:9092', 'message.timeout.ms': 4500})
    errors = []
    def delivered(err, message):
        if err:
            errors.append(str(err))
    producer.produce('sentra.scan.completed', key=scan_id, value=json.dumps(dict(id=scan_id, kind=kind, level=level)), on_delivery=delivered)
    if producer.flush(6) or errors:
        raise RuntimeError('Kafka delivery failed')

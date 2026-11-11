FROM python:3.12-slim
WORKDIR /opt/sentra
RUN pip install --no-cache-dir "celery[redis]>=5.4,<6" "psycopg[binary]>=3.2,<4" "confluent-kafka>=2.6,<3" && useradd --create-home sentra
COPY --chown=sentra:sentra . .
USER sentra
ENV HOST=0.0.0.0 PYTHONUNBUFFERED=1
EXPOSE 8765
CMD ["python","app.py"]

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/shared/src:/app/service/src
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY shared/requirements.txt /app/requirements-shared.txt
COPY services/servicenow-writer/requirements.txt /app/requirements-service.txt
RUN pip install --no-cache-dir -r /app/requirements-shared.txt -r /app/requirements-service.txt
COPY shared/src /app/shared/src
COPY services/servicenow-writer/src /app/service/src
RUN chown -R appuser:appuser /app
USER appuser
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD python -c "import servicenow_writer" || exit 1
CMD ["python", "-m", "servicenow_writer.main"]


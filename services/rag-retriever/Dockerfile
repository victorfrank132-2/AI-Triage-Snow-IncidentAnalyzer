FROM public.ecr.aws/docker/library/python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/shared/src:/app/service/src
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY shared/requirements.txt /app/requirements-shared.txt
COPY services/rag-retriever/requirements.txt /app/requirements-service.txt
RUN pip install --no-cache-dir -r /app/requirements-shared.txt -r /app/requirements-service.txt
COPY shared/src /app/shared/src
COPY services/rag-retriever/src /app/service/src
RUN chown -R appuser:appuser /app
USER appuser
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD python -c "import rag_retriever" || exit 1
CMD ["python", "-m", "rag_retriever.main"]

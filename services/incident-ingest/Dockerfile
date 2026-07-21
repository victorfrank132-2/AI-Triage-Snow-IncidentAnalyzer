FROM public.ecr.aws/lambda/python:3.12
COPY services/incident-ingest/src/ ${LAMBDA_TASK_ROOT}/
CMD ["lambda_handler.handler"]


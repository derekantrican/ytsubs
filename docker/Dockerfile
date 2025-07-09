# syntax=docker/dockerfile:1
# check=error=true

FROM public.ecr.aws/lambda/python:3.10 AS lambda-python

FROM lambda-python AS lambda-python+zip

RUN yum --noplugins -y install zip ; yum --noplugins -y clean all

FROM lambda-python AS common

COPY lambda/common/requirements.txt "${LAMBDA_DIST}/requirements.txt"
RUN pip install -r "${LAMBDA_DIST}/requirements.txt" --target "${LAMBDA_RUNTIME_DIR}/"
COPY lambda/common/*.py "${LAMBDA_TASK_ROOT}/"

FROM common AS task

COPY --from=function requirements.txt "${LAMBDA_DIST}/function-requirements.txt"
RUN pip install -r "${LAMBDA_DIST}/function-requirements.txt" --target "${LAMBDA_RUNTIME_DIR}/"
COPY --from=function * "${LAMBDA_TASK_ROOT}/"

FROM lambda-python+zip AS deploy

ARG LAMBDA_DIST=/srv
COPY --from=task "${LAMBDA_TASK_ROOT}/" "${LAMBDA_TASK_ROOT}/"

# zip ${LAMBDA_TASK_ROOT} files
RUN cd "${LAMBDA_TASK_ROOT}" && \
    zip "${LAMBDA_DIST}/deploy.zip" *

FROM task AS final

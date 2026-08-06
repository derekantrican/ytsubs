ARG PYTHON_VERSION=3.10

FROM public.ecr.aws/lambda/python:${PYTHON_VERSION} AS lambda-base

RUN yum --noplugins -y install zip ; yum --noplugins -y clean all

ARG LAMBDA_DIST=/srv
ENV LAMBDA_DIST="${LAMBDA_DIST}"

COPY requirements.txt "${LAMBDA_DIST}/requirements.txt"

# Install the specified packages
RUN ! test -s "${LAMBDA_DIST}/requirements.txt" || pip install --no-cache-dir --require-hashes -r "${LAMBDA_DIST}/requirements.txt" --target "${LAMBDA_RUNTIME_DIR}/"

# Targets

FROM lambda-base AS fetch_subscriptions
ARG LAMBDA_FUNCTION
ENV _HANDLER="${LAMBDA_FUNCTION}"

COPY --from=lambda_src *.py "${LAMBDA_TASK_ROOT}/"

RUN cd "${LAMBDA_TASK_ROOT}" && \
    zip "${LAMBDA_DIST}/deploy.zip" *

FROM lambda-base AS oauth_callback
ARG LAMBDA_FUNCTION
ENV _HANDLER="${LAMBDA_FUNCTION}"

COPY --from=lambda_src *.py "${LAMBDA_TASK_ROOT}/"

RUN cd "${LAMBDA_TASK_ROOT}" && \
    zip "${LAMBDA_DIST}/deploy.zip" *

FROM lambda-base AS oauth_start
ARG LAMBDA_FUNCTION
ENV _HANDLER="${LAMBDA_FUNCTION}"

COPY --from=lambda_src *.py "${LAMBDA_TASK_ROOT}/"

RUN cd "${LAMBDA_TASK_ROOT}" && \
    zip "${LAMBDA_DIST}/deploy.zip" *

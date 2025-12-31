FROM python:3.14-alpine AS builder

RUN apk update && apk upgrade

# poetry version available on Ubuntu 24.04
RUN pip3 install poetry==2.1.3

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry build

FROM python:3.14-alpine AS runner

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
RUN pip3 install --no-cache-dir "$(ls dist/*.whl)[prod]"

# Declare the build argument
ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

# Verify AWS CLI is installed
RUN aws --version || echo "AWS CLI installation verification"

# Set environment variables for AWS
ENV AWS_HOME=/root/.local/share/aws
# Create AWS data directory
RUN mkdir -p ${AWS_HOME}


CMD ["python3", "-m", "aws.openaev_aws"]
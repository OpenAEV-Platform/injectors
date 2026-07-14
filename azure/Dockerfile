FROM python:3.13-alpine AS builder

ENV PIP_VERSION=25.0.1

RUN apk update && apk upgrade && apk add git curl

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

RUN curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3 get-pip.py pip==${PIP_VERSION} && \
    rm get-pip.py

RUN python3 -m pip install poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install && \
    python3 -m pip install --no-cache-dir pip==${PIP_VERSION}

FROM python:3.13-alpine AS runner

ENV PIP_VERSION=25.0.1
# Stratus Red Team CLI (single self-contained Go binary).
ENV STRATUS_VERSION=2.24.0

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN apk add --no-cache curl tar libc6-compat && \
    curl -sSL "https://github.com/DataDog/stratus-red-team/releases/download/v${STRATUS_VERSION}/stratus-red-team_${STRATUS_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/stratus.tar.gz && \
    tar -xzf /tmp/stratus.tar.gz -C /usr/local/bin stratus && \
    rm /tmp/stratus.tar.gz && \
    stratus version || echo "stratus installed"

RUN if [ -n "${PYOAEV_GIT_BRANCH_OVERRIDE}" ] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git curl && \
        curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
        python3 get-pip.py pip==${PIP_VERSION} && \
        rm get-pip.py && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

CMD ["python3", "-m", "azure_injector.openaev_azure"]

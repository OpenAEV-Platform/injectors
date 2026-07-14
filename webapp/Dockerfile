FROM python:3.13-alpine AS builder

ENV PIP_VERSION=25.0.1

RUN apk update && apk upgrade && apk add curl

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

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

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

ARG PYOAEV_GIT_BRANCH_OVERRIDE

# SQLMap (pure Python) is cloned and exposed on PATH. The ZAP baseline is
# expected to be reachable as `zap-baseline.py` (mount the ZAP image or add it
# in a downstream build) for the OWASP ZAP contract.
# Pinned to a specific release tag so image contents stay reproducible and are
# not affected by upstream force-pushes to the default branch.
ARG SQLMAP_VERSION=1.10.7
RUN apk add --no-cache git && \
    git clone --depth 1 --branch ${SQLMAP_VERSION} https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap

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

CMD ["python3", "-m", "webapp_injector.openaev_webapp"]

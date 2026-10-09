FROM python:3.13-alpine AS builder

RUN apk update && apk upgrade && apk add git

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

# poetry version available on Ubuntu 24.04
RUN pip3 install poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install

FROM python:3.13-alpine AS runner

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

# Declare the build argument
ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

# Install Prowler, like the netexec injector installs its CLI, in its own
# virtual environment: the Prowler wheel ships a top-level `prowler` package
# (same import name as this injector) and pins pydantic==2.12.5, so it cannot
# share the injector's environment. lz4 and zstd have no musl wheels.
ARG PROWLER_VERSION=5.36.0
RUN apk update && apk upgrade && apk add \
    gcc \
    musl-dev
RUN python3 -m venv /opt/prowler \
    && /opt/prowler/bin/python -m pip install --no-cache-dir "prowler==${PROWLER_VERSION}" \
    && ln -s /opt/prowler/bin/prowler /usr/local/bin/prowler

CMD ["python3", "-m", "prowler"]

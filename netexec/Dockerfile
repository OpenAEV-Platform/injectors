FROM python:3.13-alpine AS builder

RUN apk --no-cache upgrade && apk --no-cache add \
    git \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

RUN pip3 install -U pip certifi

# poetry version available on Ubuntu 24.04
RUN pip3 install poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install

FROM python:3.13-alpine AS runner

# brotli-libs: the system Brotli that Pillow's FreeType loads (see the netexec install).
RUN apk --no-cache upgrade && apk --no-cache add \
    brotli-libs \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    git

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

# Declare the build argument
ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

# Install netexec. The Pillow wheels bundle Brotli 1.2.0 (CVE-2026-111497) for
# FreeType: in the same layer, replace the bundled libbrotlidec with a link to
# the system one (brotli-libs, fixed) and remove the bundled libbrotlicommon,
# which only it loads (#487).
# The link keeps the bundled name (libbrotlidec-<hash>.so.1.2.0), the one
# FreeType loads, but resolves to the system version.
RUN CFLAGS="${CFLAGS:-} -Wno-error=int-conversion" \
    pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec.git \
    && cd /usr/local/lib/python3*/site-packages/pillow.libs \
    && rm libbrotlicommon-* \
    && ln -sf /usr/lib/libbrotlidec.so.1 libbrotlidec-*

CMD ["python3", "-m", "netexec.openaev_netexec"]

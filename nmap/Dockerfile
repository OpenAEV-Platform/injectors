FROM python:3.13-alpine AS builder

RUN apk --no-cache upgrade && apk --no-cache add git

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

RUN pip3 install --no-cache-dir -U pip certifi

# poetry version available on Ubuntu 24.04
RUN pip3 install --no-cache-dir poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install

FROM python:3.13-alpine AS runner

# -sV starts the NSE engine: on Alpine nse_main.lua and nselib ship in
# nmap-nselibs and the scripts in nmap-scripts, not in nmap itself.
RUN apk --no-cache upgrade && apk --no-cache add nmap nmap-nselibs nmap-scripts
# Smoke test: service detection must start and report the host, else the
# image build fails (the -sV contract would exit 1 at run time).
RUN nmap -Pn -sT -sV --version-light -p 1 -oX - 127.0.0.1 > /tmp/nmap-smoke.xml \
    && grep -q '<host ' /tmp/nmap-smoke.xml \
    && rm -f /tmp/nmap-smoke.xml
RUN pip install --no-cache-dir -U pip certifi

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
        apk add --no-cache git && \
        pip install --no-cache-dir pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install --no-cache-dir git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

CMD ["python3", "-m", "nmap.openaev_nmap"]

FROM python:3.13-slim AS builder

RUN pip3 install poetry==2.1.3
RUN apt-get update && apt-get upgrade -y

ARG installdir=/injector
ADD . ${installdir}
RUN cd ${installdir} && poetry build

FROM python:3.13-slim AS runner

ARG installdir=/injector

# Declare the build argument
ARG PYOAEV_GIT_BRANCH_OVERRIDE
# Set to "true" to bake the heavy OSS engines (Garak, PyRIT, Promptfoo) into the image. The native
# and internal multi-turn engines always work; Garak/Promptfoo report a clear error when absent.
ARG INSTALL_OSS_ENGINES=false

COPY --from=builder ${installdir} ${installdir}
RUN cd ${installdir}/dist && pip3 install --no-cache-dir "$(ls *.whl)[prod]"

RUN if [ "${PYOAEV_GIT_BRANCH_OVERRIDE}" ] ; then \
        echo "Forcing specific version of client-python" && \
        apt-get update && apt-get install -y --no-install-recommends git && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install "git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE}" ; \
    fi

# Optional: best-effort install of the OSS red-team engines. Failures here never break the image;
# the corresponding engines simply report that the tool is unavailable.
RUN if [ "${INSTALL_OSS_ENGINES}" = "true" ] ; then \
        apt-get update && apt-get install -y --no-install-recommends nodejs npm git ; \
        pip3 install --no-cache-dir garak pyrit || echo "skip garak/pyrit" ; \
        npm install -g promptfoo || echo "skip promptfoo" ; \
    fi

# necessary for icon location
WORKDIR ${installdir}

CMD ["python3", "-m", "ai_redteam.openaev_ai_redteam"]

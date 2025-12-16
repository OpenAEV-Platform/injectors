FROM python:3.13-alpine AS build

WORKDIR /opt/openaev-injector-shodan
COPY shodan /opt/openaev-injector-shodan

# Build dependencies + pip install
RUN apk add --no-cache --virtual .build-dependencies \
    build-base git libffi-dev libxml2-dev libxslt-dev && \
    pip install --no-cache-dir -r shodan/requirements.txt && \
    apk del .build-dependencies

FROM python:3.13-alpine AS runner

WORKDIR /opt/openaev-injector-shodan

# Runtime libraries
RUN apk add --no-cache libmagic libffi libxml2 libxslt

COPY --from=build /opt/openaev-injector-shodan/shodan ./shodan
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

CMD ["python3", "-m", "shodan"]
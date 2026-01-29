FROM python:3.13-alpine AS build

WORKDIR /opt/openaev-injector-shodan

# Copy dependency files (pyproject.toml / poetry.lock / README.md)
COPY pyproject.toml poetry.lock* README.md ./

# Build dependencies
RUN apk add --no-cache --virtual .build-dependencies \
    build-base git libffi-dev libxml2-dev libxslt-dev \
    && pip3 install --no-cache-dir poetry==2.2.1 \
    && poetry config virtualenvs.create false \
    && poetry install --only main --extras prod --no-interaction --no-ansi --no-root \
    && apk del .build-dependencies

# Copy the injector
COPY shodan ./shodan

FROM python:3.13-alpine AS runner

WORKDIR /opt/openaev-injector-shodan

# Runtime libraries
RUN apk add --no-cache libmagic libffi libxml2 libxslt

COPY --from=build /opt/openaev-injector-shodan/shodan ./shodan
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

CMD ["python3", "-m", "shodan"]
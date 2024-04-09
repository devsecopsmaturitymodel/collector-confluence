FROM python:3

LABEL org.opencontainers.image.title="OWASP DSOMM metricCA collector for confluence"
LABEL org.opencontainers.image.source="https://github.com/devsecopsmaturitymodel/collector-confluence/"

COPY requirements.txt /app/requirements.txt
RUN cd /app && pip install --target=./ --no-cache-dir -r requirements.txt
COPY *.py /app
COPY schemata /app
COPY scraping_config.yaml /app

ENV CONFLUENCE_URL ""
ENV CONFLUENCE_LOGIN ""
ENV CONFLUENCE_PASSWORD ""

ENV GIT_HUB_ACCESS_TOKEN ""
ENV GIT_HUB_OWNER ""
ENV GIT_HUB_REPO ""
ENV GIT_HUB_HOSTNAME "" # for on premise github enterprise

RUN adduser collector -u 1000 --home /app --disabled-password --gecos '' --shell /bin/bash
USER collector

ENTRYPOINT ["python3", "/app/confluence_collector.py"]
CMD [ "/app/scraping_config.yaml" ]

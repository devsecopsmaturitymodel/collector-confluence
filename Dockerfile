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

ENTRYPOINT ["python3", "/app/confluence_collector.py"]
CMD ["--out-path", "/tmp/out", "/app/scraping_config.yaml"]


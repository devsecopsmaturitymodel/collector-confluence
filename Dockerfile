FROM python:3

LABEL org.opencontainers.image.title="OWASP DSOMM metricCA collector for confluence"
LABEL org.opencontainers.image.source="https://github.com/devsecopsmaturitymodel/collector-confluence/"

COPY requirements.txt /app/requirements.txt
RUN cd /app && pip install --target=./ --no-cache-dir -r requirements.txt
COPY *.py /app
COPY schemata /app

ENV CONFLUENCE_URL ""
ENV CONFLUENCE_LOGIN ""
ENV CONFLUENCE_PASSWORD ""

CMD "/app/confluence_collector.py"


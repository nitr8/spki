# Stage 1: render the Markdown docs to simple HTML pages.
FROM python:3.13-slim-bookworm AS docs
RUN pip install --no-cache-dir markdown==3.7
WORKDIR /src
COPY build_docs.py ./
COPY docs/ ./docs/
RUN python3 build_docs.py /src /out

# Stage 2: runtime image.
FROM python:3.13-slim-bookworm

# bash + openssl are required by the PKI scripts and the dashboard (it shells out
# to `openssl`); vim-tiny provides `vi` for the interactive config edit step.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash openssl vim-tiny ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# PKI scripts + templates are baked into the image.
# ca/ and issued/ are NOT copied; they are mounted at runtime (see docker-compose.yml).
COPY --chmod=0755 init_ca.sh cert_gen.sh docker-entrypoint.sh ./
COPY templates/ ./templates/
# Default settings; normally overridden by bind-mounting your own pki.env.
COPY pki.env ./pki.env

# Dashboard: Python server + static page it serves.
COPY cert_dashboard.py ./cert_dashboard.py
COPY index.html ./www/index.html
# The container runs as an arbitrary UID; `serve` publishes the (public) root CA
# certificate into www/ so clients can download it from the dashboard.
# Documentation linked from the page footer (rendered to HTML at build time).
COPY --from=docs /out/ ./www/
RUN chmod 0777 /app/www

# Short alias so `docker compose exec pki pki cert nas` works.
RUN ln -s /app/docker-entrypoint.sh /usr/local/bin/pki

# vi wants a writable HOME; the container runs as an arbitrary UID in compose.
ENV HOME=/tmp \
    EDITOR=vi \
    TERM=xterm \
    PYTHONUNBUFFERED=1 \
    PKI_HTTP_PORT=8080 \
    PKI_HTTPS_PORT=8443

# State lives here (mount these).
VOLUME ["/app/ca", "/app/issued"]

EXPOSE 8080 8443

# Only meaningful while running `serve`; harmless otherwise.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python3 -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/__health.json' % os.environ.get('PKI_HTTP_PORT','8080'), timeout=3)" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["help"]

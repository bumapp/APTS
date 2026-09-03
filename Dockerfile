# ---------------------------------------------------------------------------
#  APTS shared image.
#
#  One image, many roles.  The docker-compose service definition selects the
#  Python module to run (``orchestrator.main``, ``agent.main``, etc.) via the
#  container's ``command:`` — the same image starts as an orchestrator, an
#  agent, the MCP tools bundle, or the sandbox depending on the command line.
#
#  Why python:3.11-slim-bookworm?
#     * Python 3.11 has one more year of ecosystem maturity than 3.12.
#     * Bookworm (Debian 12) is the current LTS with security support until
#       ~2028, and pins the OS layer to a specific stable release.
#     * slim is small (~130 MB base) but keeps enough of Debian around to
#       install psycopg's compiled binary wheels without surprises.
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm

# Non-root user for all runtime code
RUN groupadd --system --gid 1000 apts \
 && useradd  --system --uid 1000 --gid apts --shell /usr/sbin/nologin apts

# Minimum system packages: openssl for cert manipulation, ca-certificates for
# the base OS trust store.  Everything else comes from wheels.
#
# Fetch over HTTPS: networks with an intercepting HTTP proxy corrupt apt's
# clearsigned InRelease files ("got 'NOSPLIT'").  ca-certificates ships in the
# base image, so https works before we install anything.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' \
        /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list 2>/dev/null; \
    apt-get update \
 && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
        tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so image-layer caching works across code edits
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Only mcp-tools' crawl tool drives a browser, but every service shares this
# one image (see docker-compose.yml), so Chromium is installed here once for
# all of them. `--with-deps` pulls in the OS libraries (fonts, libnss3, etc.)
# headless Chromium needs, which is why this still runs as root. Shared,
# world-readable path so the non-root `apts` user (below) can launch it.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install --with-deps chromium

# Copy the source last so a code edit only busts the final layer
COPY shared/       /app/shared/
COPY orchestrator/ /app/orchestrator/
COPY agent/        /app/agent/
COPY mcp_tools/    /app/mcp_tools/
COPY sandbox/      /app/sandbox/
# The vuln/exploit workers import the agentic loops from here. The HackTricks
# corpus is excluded by .dockerignore — those tools run in mcp-native, not here.
COPY mcp_native/   /app/mcp_native/

# Directory where each service expects to find its TLS cert and the trust bundle
RUN mkdir -p /etc/apts && chown -R apts:apts /etc/apts /app /ms-playwright

USER apts

# tini gives us proper signal handling for uvicorn on SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command is intentionally missing; each service supplies its own.

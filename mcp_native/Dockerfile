# Isolated image for the native MCP server (mcp_native/).
#
# Separate from the shared apts-skeleton image because the MCP SDK pulls a
# heavier, newer dependency set (pydantic>=2.12, starlette, uvicorn, httpx2)
# than the six agents pin. Keeping it here means the agents' image is untouched.
FROM python:3.11-slim-bookworm

RUN groupadd --system --gid 1000 apts \
 && useradd  --system --uid 1000 --gid apts --shell /usr/sbin/nologin apts

WORKDIR /app

COPY mcp_native/requirements.txt /app/mcp_native/requirements.txt
RUN pip install --no-cache-dir -r /app/mcp_native/requirements.txt

# The crawl tool drives headless Chromium via Playwright. Install the browser
# and its system libraries once, into a shared path (as root, before USER apts).
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install --with-deps chromium

# shared.db (recon lookup), the mcp_native package, and mcp_tools — the crawl
# tool reuses the tested browser crawler that lives under mcp_tools.
COPY shared/     /app/shared/
COPY mcp_native/ /app/mcp_native/
COPY mcp_tools/  /app/mcp_tools/

RUN mkdir -p /etc/apts && chown -R apts:apts /app /etc/apts /ms-playwright
USER apts

CMD ["python", "-m", "mcp_native.server", "--http"]

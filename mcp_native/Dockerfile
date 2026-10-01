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

# Recon tools, added AFTER the heavy Playwright layer so rebuilds don't re-pull
# Chromium: katana (crawl/endpoint enumeration) + ffuf (content/param fuzzing),
# both Go release binaries, and arjun (hidden-parameter discovery) via pip.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip \
 && curl -sSL https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip -o /tmp/katana.zip \
 && unzip -o /tmp/katana.zip katana -d /usr/local/bin \
 && curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o /tmp/ffuf.tgz \
 && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
 && chmod +x /usr/local/bin/katana /usr/local/bin/ffuf \
 && pip install --no-cache-dir arjun \
 && rm -f /tmp/katana.zip /tmp/ffuf.tgz \
 && rm -rf /var/lib/apt/lists/* \
 && katana -version && ffuf -V && arjun --help >/dev/null 2>&1 && echo "recon tools OK"

# SecLists wordlists (curated subset) for ffuf. A sparse checkout keeps only the
# web-content + LFI/param lists we need, not the full ~1GB repo. The ffuf tool
# exposes these by name so the recon agent picks the right list per task.
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && git clone --depth 1 --filter=blob:none --sparse \
      https://github.com/danielmiessler/SecLists.git /opt/seclists \
 && git -C /opt/seclists sparse-checkout set \
      Discovery/Web-Content Fuzzing/LFI \
 && apt-get purge -y --auto-remove git && rm -rf /var/lib/apt/lists/* \
 && ls /opt/seclists/Discovery/Web-Content/common.txt && echo "seclists OK"

# shared.db (recon lookup) and the mcp_native package (which now carries its own
# browser crawler under mcp_native/crawler/ — no longer the retired mcp_tools).
COPY shared/     /app/shared/
COPY mcp_native/ /app/mcp_native/

RUN mkdir -p /etc/apts && chown -R apts:apts /app /etc/apts /ms-playwright
USER apts

CMD ["python", "-m", "mcp_native.server", "--http"]

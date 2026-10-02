"""xss_prove — navigate to the page, inject, and prove XSS executes (deterministic).

You give the tool the page, the injection point, and the payload:

* ``spa_page``   — the page where the value is rendered into the DOM: a full URL, or
                   a relative route/path (e.g. "/#/photo-wall") resolved against
                   ``target``. This is the client route that displays the value, not
                   the API/backend endpoint that returns raw data.
* ``target``     — the target's base URL (from recon), used to make a relative
                   ``spa_page`` absolute.
* ``parameter``  — the injection point inferred from the original request.
* ``payload``    — your XSS payload, carrying a unique nonce in its alert.

The tool opens headless Chromium (Playwright), navigates to the page, injects
the payload at ``parameter`` — first by filling a matching input field on the page,
then, if that yields nothing, by putting it in the parameter in the URL — and
watches for real execution: a ``dialog`` carrying your nonce. Reflection alone is
never counted as proof, and a navigation that fails (e.g. a relative or invalid
URL) returns an error rather than a verdict. On failure it returns what it saw
(reflected-but-not-executed context, page errors) so you can adjust the payload,
parameter, or page.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote
from uuid import uuid4


def _snippet(text: str, needle: str) -> str | None:
    i = text.find(needle)
    if i < 0:
        return None
    start, end = max(0, i - 80), min(len(text), i + len(needle) + 80)
    return ("…" if start else "") + text[start:end] + ("…" if end < len(text) else "")


def _inject_url(spa_page: str, parameter: str, payload: str) -> str:
    """Put ``parameter=payload`` into the query — in the hash fragment when the
    page uses hash-based client routing, else in the normal query string."""
    enc = quote(payload, safe="")
    if "#" in spa_page:
        base, frag = spa_page.split("#", 1)
        sep = "&" if "?" in frag else "?"
        return f"{base}#{frag}{sep}{parameter}={enc}"
    head, _, tail = spa_page.partition("#")
    sep = "&" if "?" in head else "?"
    frag = f"#{tail}" if tail else ""
    return f"{head}{sep}{parameter}={enc}{frag}"


def _resolve(spa_page: str, target: str | None) -> str | None:
    """Return an absolute page URL. Accepts a full URL in ``spa_page``, or a
    relative route/path resolved against the ``target`` base — so the model can
    hand a route like "/#/x" and the target separately, like a browser resolving a
    link against its origin."""
    sp = (spa_page or "").strip()
    if sp.startswith(("http://", "https://")):
        return sp
    base = (target or "").strip()
    if not (base.startswith("http://") or base.startswith("https://")):
        return None
    base = base.rstrip("/")
    if sp.startswith("#"):
        return f"{base}/{sp}"
    if sp.startswith("/"):
        return f"{base}{sp}"
    return f"{base}/{sp}" if sp else base


# Selectors to try when locating the injection field on the page, most specific
# first — derived only from the parameter name and generic HTML input types, never
# any one application's markup.
def _field_selectors(parameter: str) -> list[str]:
    p = parameter.replace('"', "")
    return [f'input[name="{p}"]', f'textarea[name="{p}"]', f'#{p}',
            f'[name="{p}"]', 'input[type="search"]', 'input[type="text"]', 'textarea']


async def xss_prove(
    spa_page: str,
    parameter: str,
    payload: str,
    target: str | None = None,
    nonce: str | None = None,
    wait_ms: int = 2500,
    store_url: str | None = None,
    store_body: Any = None,
    store_method: str = "POST",
    store_headers: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    cookies: list[dict] | None = None,
) -> dict[str, Any]:
    """Navigate to a page, inject a payload at a parameter, and prove XSS executes.

    Proof is EXECUTION: the tool confirms ('proven': true) ONLY when a JavaScript
    dialog carrying your nonce actually fires in the browser. Reflection alone is
    never proof.

    REFLECTED / DOM XSS: give spa_page + parameter + payload; the tool injects at
    the parameter (in a matching field, else the URL) and checks execution.

    STORED XSS: also give store_url + store_body — the tool first sends that request
    (POST by default) to STORE the payload, THEN navigates spa_page (the page that
    renders stored content) and checks execution there. Put the payload inside
    store_body at the field that gets displayed; get store_url and its shape from the
    recorded POST requests recon observed.

    Args:
        spa_page: The page where the value is rendered into the DOM — a full URL, or
            a relative route/path resolved against ``target``.
        parameter: The injection point (for reflected/DOM). For pure stored XSS the
            payload is in ``store_body``; parameter can name the stored field.
        payload: The XSS payload, with a unique token in its alert.
        target: The target's base URL (from recon); resolves relative URLs.
        nonce: The token your alert prints — proof is tied to it.
        wait_ms: How long to wait after each injection for the payload to run.
        store_url: Optional. The endpoint that STORES content (stored XSS) — a full
            URL or a route resolved against ``target``.
        store_body: The body to send to store_url (dict/JSON or string) with the
            payload embedded in the field that will be displayed.
        store_method: HTTP method for the store request (default POST).
        store_headers: Headers for the store request (e.g. an auth token).
        headers: Session headers applied to the whole browser context (navigation
            AND the store request) — e.g. an Authorization header for an
            authenticated run. Usually supplied automatically by the engagement.
        cookies: Session cookies ([{name, value}, ...]) added to the browser context
            for the target origin, so a page behind a login renders authenticated.
            Usually supplied automatically by the engagement.
    """
    from playwright.async_api import async_playwright

    page_url = _resolve(spa_page, target)
    if not page_url:
        return {"proven": False,
                "error": f"could not resolve a full URL from spa_page={spa_page!r}",
                "guidance": "Either put a full URL in spa_page, or pass the target's "
                            "base URL in `target` (from the recon 'Target:' line) plus "
                            "the route/path in spa_page — e.g. target='http://host:3000/', "
                            "spa_page='/#/photo-wall'."}
    if not nonce:
        nonce = f"APTS-{uuid4().hex[:8]}"
    wait_ms = min(max(int(wait_ms), 0), 6000)
    dialogs: list[str] = []
    page_errors: list[str] = []
    injection_point = None
    strategy = None
    navigated = False
    store_status = None

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(chromium_sandbox=False, args=["--no-sandbox"])
            try:
                # A session-aware context: extra headers (e.g. Authorization) apply
                # to navigation and the store request; cookies are added for the
                # target origin so a page behind a login renders authenticated.
                context = await browser.new_context(extra_http_headers=headers or {})
                if cookies:
                    jar = [{"name": c["name"], "value": str(c.get("value", "")),
                            "url": page_url}
                           for c in cookies if isinstance(c, dict) and c.get("name")]
                    if jar:
                        try:
                            await context.add_cookies(jar)
                        except Exception as exc:  # noqa: BLE001 — bad cookie shape
                            page_errors.append(f"add_cookies: {exc}"[:160])
                page = await context.new_page()

                async def on_dialog(dialog):
                    dialogs.append(dialog.message)
                    try:
                        await dialog.dismiss()
                    except Exception:  # noqa: BLE001
                        pass

                page.on("dialog", on_dialog)
                page.on("pageerror", lambda e: page_errors.append(str(e)[:200]))

                async def _goto(url: str) -> bool:
                    nonlocal navigated
                    try:
                        await page.goto(url, wait_until="load", timeout=15000)
                        navigated = True
                        return True
                    except Exception as exc:  # noqa: BLE001
                        page_errors.append(f"nav {url}: {exc}"[:200])
                        return False

                # 0) Stored XSS: send the store request first so the payload is
                #    persisted, then the navigation below will render it.
                if store_url:
                    su = _resolve(store_url, target) or store_url
                    hdrs = dict(store_headers or {})
                    body = store_body
                    if isinstance(body, (dict, list)):
                        data = json.dumps(body)
                        hdrs.setdefault("content-type", "application/json")
                    else:
                        data = None if body is None else str(body)
                    try:
                        resp = await page.request.fetch(
                            su, method=(store_method or "POST").upper(),
                            data=data, headers=hdrs, timeout=15000)
                        store_status = resp.status
                    except Exception as exc:  # noqa: BLE001
                        store_status = None
                        page_errors.append(f"store {su}: {exc}"[:200])

                if store_url:
                    # Stored XSS: the payload is already persisted — just render the
                    # page and watch for execution. Do not re-inject.
                    if await _goto(page_url):
                        await page.wait_for_timeout(wait_ms)
                        injection_point = f"stored:{parameter}"
                        strategy = "stored"
                else:
                    # Reflected/DOM XSS: navigate, then inject at the parameter.
                    # 1) Try a matching input field on the page.
                    if await _goto(page_url):
                        await page.wait_for_timeout(600)  # let the SPA settle
                        for sel in _field_selectors(parameter):
                            try:
                                el = await page.query_selector(sel)
                            except Exception:  # noqa: BLE001
                                el = None
                            if not el:
                                continue
                            try:
                                await el.fill(payload)
                                await el.press("Enter")
                                injection_point = f"field {sel}"
                                strategy = "form"
                                await page.wait_for_timeout(wait_ms)
                            except Exception as exc:  # noqa: BLE001
                                page_errors.append(f"fill {sel}: {exc}"[:160])
                            break
                    # 2) If nothing fired, inject via the parameter in the URL.
                    if not any(nonce in d for d in dialogs):
                        if await _goto(_inject_url(page_url, parameter, payload)):
                            await page.wait_for_timeout(wait_ms)
                            injection_point = injection_point or f"url:{parameter}"
                            strategy = strategy or "url"

                html = await page.content() if navigated else ""
                title = await page.title() if navigated else ""
            finally:
                await browser.close()
    except Exception as exc:  # noqa: BLE001
        return {"proven": False, "error": f"browser failed: {exc}",
                "guidance": "The headless browser could not run this; check spa_page."}

    # If the browser never loaded the page, nothing was tested — do not pretend.
    if not navigated:
        return {"spa_page": page_url, "parameter": parameter, "proven": False,
                "dialog_fired": False, "page_errors": page_errors[:5],
                "guidance": "Navigation FAILED — the page never loaded (see "
                            "page_errors). Pass a full absolute URL (scheme + host + "
                            "route); a relative path is invalid."}

    dialog_fired = len(dialogs) > 0
    nonce_matched = any(nonce in d for d in dialogs)
    proven = nonce_matched
    reflected = _snippet(html, nonce) if (not proven and nonce in html) else None

    if proven:
        guidance = (f"PROVEN XSS: JavaScript executed — a dialog carrying {nonce!r} "
                    f"fired after injecting at {injection_point}. Deterministic proof. "
                    f"Give VERDICT: PROVEN.")
    elif dialog_fired:
        guidance = (f"A dialog fired but without your nonce ({dialogs[:2]}). Put "
                    f"{nonce!r} inside the alert so the proof is unambiguous, and retry.")
    elif reflected is not None:
        guidance = (f"REFLECTED BUT NOT EXECUTED at {page_url}: your token is in the "
                    f"page but did not run — wrong context/sink or it was escaped. "
                    f"Context: {reflected}. Try other injection contexts/payload "
                    f"shapes, or check this is the page where the value is rendered.")
    else:
        guidance = (f"No execution and {nonce!r} not found on {page_url}. Likely the "
                    f"wrong page (is this where {parameter!r}'s value is rendered into "
                    f"the DOM?), the wrong parameter, or a filtered payload. Adjust "
                    f"one and retry.")

    return {
        "spa_page": page_url,
        "parameter": parameter,
        "nonce": nonce,
        "injection_point": injection_point,
        "strategy": strategy,
        "proven": proven,
        "dialog_fired": dialog_fired,
        "dialogs": dialogs[:5],
        "stored": bool(store_url),
        "store_status": store_status,
        "reflected_not_executed": reflected,
        "page_title": title[:200],
        "page_errors": page_errors[:5],
        "guidance": guidance,
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Prove XSS by EXECUTING it in a real headless browser. Give the page where "
        "the value is rendered into the DOM (spa_page — the client route that "
        "displays the value, not the API/backend endpoint; a full URL, or a relative "
        "route resolved against target, the base URL from recon), the injection "
        "point (parameter), and your payload (with a "
        "unique token in its alert, passed as nonce). The tool navigates, injects the "
        "payload at the parameter (via a matching input field, else via the URL), and "
        "confirms ('proven': true) ONLY on real execution — a dialog carrying your "
        "nonce. For STORED XSS, also pass store_url + store_body (with the payload in "
        "the displayed field): the tool POSTs that first to store the payload, then "
        "views spa_page and checks execution. Reflection is not proof; on failure it "
        "returns what it saw (including navigation errors). Covers reflected, DOM, and "
        "stored XSS."
    ))(xss_prove)
    return ["xss_prove"]

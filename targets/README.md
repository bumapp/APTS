# Target lab

Three deliberately vulnerable "AI" apps on different stacks, for benchmarking the
recon/exploit tooling. See [INTENDED-VULNS.md](INTENDED-VULNS.md) for the full list
of planted issues per site. **Disposable lab only.**

| site | stack | internal URL (recon targets this) |
|---|---|---|
| neuralnotes | Python / Flask / SQLite | `http://neuralnotes:5000` |
| chatforge | Node / Express | `http://chatforge:3100` |
| promptvault | PHP / SQLite | `http://promptvault:8080` |

## Prereq
The main APTS stack must be up first (it owns the `apts-target` network):
```bash
docker compose up -d        # from the repo root
```

## Select a target (only one up at a time)
```bash
cd targets
./select.sh neuralnotes     # or chatforge | promptvault
./select.sh status          # what's running
./select.sh down            # stop all
```

## View it from your PC
The active site is always published at **http://localhost:8000** (open it in your
Windows browser — WSL forwards localhost). Only one site binds :8000 at a time, so
switching is just `./select.sh <other-site>`.

## How recon reaches it
mcp-native and the agents are on the same `apts-target` network, so they reach the
active site by its **internal hostname** (e.g. `http://neuralnotes:5000`) — that's
the URL you point recon / `crawl_v2` / an engagement at.

## A note on the "selector UI"
`select.sh` is the selector. A tiny web UI could sit in front of this later (a page
that lists the three sites and calls the same compose profiles), but the script is
the single source of truth for "exactly one site up, published on :8000".

# Docs

**New to the project? Read [`system-flow.md`](system-flow.md) first.** It explains
what APTS does, how the six agents fit together, and the rules you must not
break. Fifteen minutes.

| File | What it is | Who it's for |
| --- | --- | --- |
| [`system-flow.md`](system-flow.md) | How the whole system works, in plain language | **Start here.** Anyone joining the project |
| [`system-flow.html`](system-flow.html) | The same thing as a web page — self-contained, opens offline, no CDN | Same, if you prefer a browser or want to send it to someone |
| [`tool-call-flow.md`](tool-call-flow.md) | Deep dive on one request: how an agent's tool call is authorised, scoped, and executed | Once you're working on `mcp_tools/` |
| `deployment.png` | Container topology diagram | Anyone deploying it |

The two `system-flow` files are kept in sync by hand. If you change one, change
the other.

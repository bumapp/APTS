# Standalone tool validation vs NeuralNotes (http://neuralnotes:5000)

Run before wrapping as MCP tools, to confirm each works + what it adds over crawl_v2.
Raw outputs: tool_katana_neuralnotes.txt, tool_ffuf_paths.txt, tool_ffuf_idor.txt,
tool_arjun_search.txt, tool_arjun_summarize.txt.

| tool | command (in mcp-native) | result |
|---|---|---|
| **katana** | `katana -u $U/ -d 2 -silent` | crawled: `/`, `/login`, `/search`, `/summarize` (link crawl, ≈ crawl_v2) |
| **ffuf** (paths) | `ffuf -u $U/FUZZ -w common.txt -mc 200,301,302,405` | `search`, `summarize`, `login` |
| **ffuf** (IDOR) | `ffuf -u $U/api/note/FUZZ -w ids.txt -mc 200` | **1, 2, 3, 4** — the unlinked `/api/note/<id>` IDOR crawl_v2 could NOT find |
| **arjun** (search) | `arjun -u $U/search -m GET` | hidden param **`q`** |
| **arjun** (summarize) | `arjun -u $U/summarize -m GET` | hidden param **`url`** |

## Takeaway
- **katana** ≈ crawl_v2 for link discovery (useful for deep/JS crawl & as a cross-check).
- **ffuf** closes the **unlinked-endpoint** gap: path fuzzing + ID fuzzing found the IDOR
  notes that no crawler could reach.
- **arjun** closes the **hidden-parameter** gap: confirms the injectable params (`q`,`url`)
  an endpoint accepts — exactly what the vuln/exploit stages need.

## Notes for the MCP wrappers
- katana needs a writable HOME → invoke with `HOME=/tmp`.
- arjun stdout is very noisy (per-chunk progress) → the wrapper must parse only the
  "Parameters found:" line (or use `-oJ <file>` JSON output).
- ffuf: use `-s` (silent) + `-mc`/`-fs` filtering; return the matched words/paths.

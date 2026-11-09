# Rein's QA Tool

A terminal UI for managing the PRS Beheer API: organizations, certificates and
clients, plus testing `/clients/resolve`.

It is a single script with inline dependencies; [uv](https://docs.astral.sh/uv/)
installs them on first run.

## Running

```bash
# Local API (http://localhost:8512)
uv run reins_qa_tool.py

# Test environment: needs the eduVPN tunnel and a client cert signed by the dev mTLS CA
uv run reins_qa_tool.py --env test --cert client.crt --key client.key

# Connection check only (no TUI)
uv run reins_qa_tool.py --env test --cert client.crt --key client.key --check
```

Every flag has a `BEHEER_*` environment variable, so you can set them once:

```bash
export BEHEER_ENV=test BEHEER_CERT=/path/client.crt BEHEER_KEY=/path/client.key
uv run reins_qa_tool.py
```

See `uv run reins_qa_tool.py --help` for all options, including `--cacert`,
`--insecure`, `--token`, and fetching a bearer token with `--oauth-url`.

### Test environment access

`pseudoniemendienst.beheer.test.gf.irealisatie.nl` is protected at the gateway by:

1. Traefik mTLS: the client cert must be signed by `dev-mtls-ca`.
2. An IP allowlist: connect through the eduVPN tunnel.
3. Kong `cert-cn`, which passes the cert's CN on as `x-gf-act-cn`.

There is no OAuth on the beheer host. Alternatively, skip the gateway with
`kubectl -n prs-v0-2 port-forward svc/prs-beheer-api-service 8512:8080` and run
the tool without flags.

## Keys

| Key | Action |
|---|---|
| `1` / `2` / `3` | Focus organizations / clients / certificates |
| `n` / `e` / `d` | New / edit / delete in the active table |
| `x` | Show or hide soft-deleted records |
| `v` | Test `POST /clients/resolve` (pre-filled from the selection) |
| `g` | Create a demo organization with a certificate and a client |
| `h` | Health and version |
| `c` | Copy the selected ID |
| `l` | Show or hide the HTTP log |
| `r` / `q` | Refresh / quit |

In forms: Tab / Shift+Tab move between fields, Space toggles a checkbox,
Ctrl+S saves, Esc cancels.

## Tests

Headless tests against an in-memory fake of the API:

```bash
uv run --script tests/fake_api_test.py
uv run --script tests/focus_test.py
```

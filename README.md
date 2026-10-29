# lleap

SSRF and open-redirect tester for the command line. Give lleap a URL
template from your own application — for example a fetcher endpoint or a
redirect parameter — and it fires a curated payload set at it, then reports
which values got fetched, redirected, blocked, or left undecided.

Standard library only. No dependencies, no network calls beyond the target
you specify.

## What it tests

| Group | Payloads | Covers |
| --- | --- | --- |
| `metadata` | 6 | Cloud metadata endpoints (AWS, GCP, Alibaba, ECS) |
| `localhost` | 10 | Loopback in decimal, hex, octal, shortened, and IPv6 forms |
| `parser` | 4 | Userinfo / fragment / encoding tricks that fool naive validators |
| `internal` | 8 | Internal services on loopback (Redis, MySQL, Postgres, Mongo, Docker API, …) |
| `scheme` | 4 | `file://`, `gopher://`, `dict://`, `ftp://` |
| `redirect` | 7 | Absolute, protocol-relative, encoded, and `javascript:`/`data:` redirect values |

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Llunatics/lleap.git
cd lleap
python3 -m venv .venv
.venv/bin/pip install .
```

This installs the `lleap` command.

## Usage

### Scan a target

The target URL must contain the `{payload}` placeholder, which lleap
replaces with each payload value (URL-encoded).

```bash
lleap scan --target 'http://127.0.0.1:8901/fetch?url={payload}'
```

```bash
lleap scan --target 'http://localhost:3000/redirect?next={payload}' \
  --sets redirect
```

Options:

| Flag | Meaning |
| --- | --- |
| `--sets` | Comma-separated payload groups (default: all) |
| `--timeout` | Per-request timeout in seconds (default: 5) |
| `--delay` | Pause between requests in seconds (default: 0) |
| `--json FILE` | Also write the full report as JSON |
| `--allow-public-target` | Required when the target resolves to a public IP |
| `--quiet` | Skip the warning banner |

Exit code is `1` when any payload is classified `FETCHED` or
`OPEN-REDIRECT`, `0` otherwise, `2` for usage errors.

### Try it against the bundled lab

The lab is a deliberately vulnerable fetcher + redirector that binds
127.0.0.1 only. It exists so the scanner can be proven against known
behaviour, without pointing payloads at a real application.

```bash
lleap demo
```

`demo` starts the lab on a free loopback port, scans it with the full
catalog, and prints the canary proof: a hit on `/canary/demo` means the
lab server itself requested that URL — ground truth for a server-side
fetch, not a heuristic guess.

To run the lab standalone (for example, to test another tool against it):

```bash
lleap lab --port 8901
# Endpoints: /fetch?url=  /redirect?next=  /canary/<token>  /canary-hits
```

### List the payload catalog

```bash
lleap list-payloads
lleap list-payloads --sets metadata,parser
```

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `FETCHED` | Evidence the target fetched the payload URL server-side (lab fetch report, payload host echoed in the body, or a cloud metadata marker) |
| `OPEN-REDIRECT` | The target redirected the client to the payload host, or reflected a `javascript:`/`data:` URI into the `Location` header |
| `BLOCKED` | The target refused the value (4xx with a block keyword, or a lab fetch refusal) |
| `UNCLEAR` | No fetch, block, or redirect evidence — the raw status and body length are reported for manual judgment |
| `ERROR` | The request to the target itself failed |

Verdicts are evidence grades, not proof of exploitability. A `FETCHED`
result against the lab is ground truth (canary log); against an arbitrary
target it means "worth confirming by hand".

Two deliberate safety behaviours:

- **Redirects are never followed.** Following one would destroy the
  open-redirect evidence and send requests to the payload host.
- **Public targets need `--allow-public-target`.** Loopback and private
  targets are always allowed; anything else requires an explicit opt-in,
  so a typo cannot turn a scan into traffic against someone else's
  infrastructure. The check covers IPv4 and IPv6 (including `[::1]`)
  and refuses a hostname that resolves to a mix of local and public
  addresses unless the flag is given.

Server-supplied strings are stripped of ANSI escape sequences and control
characters before they reach the terminal or a JSON report.

## Safety

Only test applications you own or have written permission to test. The
lab server is intentionally vulnerable — never expose its port beyond
loopback.

## Tests

```bash
python3 -m unittest discover -s tests
```

28 tests, standard library only, fully offline: the lab runs in a thread
on 127.0.0.1, so integration tests exercise real fetching, redirect
capture, and canary proof without touching the network.

## License

MIT. See [LICENSE](LICENSE).

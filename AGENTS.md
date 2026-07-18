# AGENTS.md

Compact guidance for OpenCode sessions working in this repo. Pure-C, zero-dependency TLS/HTTP client. No build system, no tests, no CI — everything is direct `gcc` commands.

## Layout

- `plancktls/` — all source. Three **independent, mutually exclusive** library variants (do NOT compile two together):
  - `planck.c` / `planck.h` — primary variant; supports `-DPLANCK_DEBUG=1` and the full `planck_config` (see below).
  - `plancknd.c` / `plancknd.h` — "no-debug" variant: debug strings pre-stripped, smaller binary. Use without the `-D` flag.
  - `planckold.c` — legacy copy; prefer `planck.c` unless asked.
- `plancktls/test.c`, `plancktls/test_multiple.c` — example programs, not a test suite. They hit live HTTPS endpoints (e.g. `dstat.returnstress.st`) and need outbound network on port 443/80.
- Root has only `README.md` and `LICENSE`.

## Critical: variants are NOT interchangeable

`planck.h` and `plancknd.h` define **different** `planck_config` structs:

- `planck.h`: `{ tls_version, http_version, ignore_cert, ja3_profile }`
- `plancknd.h`: `{ tls_version, http_version }` only

Match the header to the `.c` you compile against. Using the wrong header produces silent field mismatches or compile errors. `test_multiple.c` sets `.ignore_cert` and `.ja3_profile`, so it only works with `planck.h` + `planck.c`.

## Build commands

README shows `test.c planck.c` as if at repo root — **they are in `plancktls/`**. Use paths from repo root:

```bash
# size-optimised (no debug)
gcc -Os -s -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -fno-unwind-tables -fno-asynchronous-unwind-tables \
    plancktls/test.c plancktls/planck.c -lpthread -o planck_test

# debug build (verbose stderr logging)
gcc -Os -DPLANCK_DEBUG=1 -s -ffunction-sections -fdata-sections \
    -Wl,--gc-sections plancktls/test.c plancktls/planck.c -lpthread -o planck_debug

# multi-connection example (requires planck.h variant)
gcc -Os -s ... plancktls/test_multiple.c plancktls/planck.c -lpthread -o test_multiple
```

For minimum binary size: `upx --ultra-brute --lzma --force <file>` after linking.

## Verification

There is no `make`, `check`, or test runner. To verify a change:
1. Compile both `test.c` and `test_multiple.c` against `planck.c` (gcc only needs to succeed — no output difference is fine if there's no network).
2. If outbound HTTPS is available, run `./planck_test https://example.com` and `./test_multiple https://example.com` to confirm a real handshake + response.
3. There is no lint / typecheck step.

## Security constraints (do not "fix" without asking)

- Certificate validation is intentionally **not** implemented — `ignore_cert` exists but expiry/hostname/chain checks are absent by design. Do not add validation silently; it's a documented limitation in the README.
- All crypto primitives (X25519, SHA-256, AES-128-GCM, ChaCha20-Poly1305) are hand-written in `planck.c`; treat them as educational, not hardened.

## Workflow notes

- Not a git repo in this checkout; don't assume `git` operations work without checking.
- Source is single-file C (`planck.c` ~1.8k lines). No packages, no submodules, no generated code, no migrations.
- API surface is four functions: `planck_init`, `planck_connect`, `planck_request`, `planck_close`. Keep that contract stable across variants.
this is 50% ai slop and 50% human trust

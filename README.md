# PlanckTLS

**A compact, zero-dependency TLS 1.3/1.2 and HTTP/2/1.1 client in pure C.**

PlanckTLS is a from‑scratch implementation of modern web protocols, optimized for minimal binary size and no external dependencies. It runs on standard C libraries and pthreads, compiles to as little as 16‑24 KB, and includes custom cryptographic primitives (X25519, AES‑128‑GCM, ChaCha20‑Poly1305, SHA‑256).

> **Use case**  
> Designed for IoT devices, embedded systems, and environments where a tiny, self‑contained TLS stack is essential. Also excellent for learning how TLS 1.3, HTTP/2, and crypto primitives are built.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [API Usage](#api-usage)
- [JA3 Fingerprinting](#ja3-fingerprinting)
- [Debug Output](#debug-output)
- [Minimising Binary Size](#minimising-binary-size)
- [Configuration Options](#configuration-options)
- [Limitations & Security Warning](#limitations--security-warning)
- [Testing](#testing)
- [Maintenance & Status](#maintenance--status)
- [License](#license)

---

## Features

- **Protocol Support**  
  TLS 1.3, TLS 1.2, HTTP/2, and HTTP/1.1 (client only).
- **Zero Dependencies**  
  Only `libc` and `pthread`. No OpenSSL, mbedTLS, or any external crypto library.
- **Custom Cryptography**  
  Includes hand‑written implementations of:
  - X25519 key exchange
  - SHA‑256
  - AES‑128‑GCM (encrypt/decrypt)
  - ChaCha20‑Poly1305 (encrypt/decrypt)
- **Tiny Footprint**  
  Stripped binaries typically range from **16 KB to 24 KB** (with UPX) (see [compilation flags](#minimising-binary-size)).
- **Configurable**  
  Mix and match TLS and HTTP versions via a simple configuration struct.
- **Thread‑Safe**  
  Library initialisation is protected by a mutex.
- **JA3 Support**  
  Built‑in presets to mimic Chrome’s TLS fingerprint.

---

## Quick Start

### 1. Clone and Compile

```bash
git clone https://github.com/Poulfyyy/PlanckTLS.git
cd PlanckTLS
```

Compile the included test program with size‑optimised flags:

```bash
gcc -Os -s -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -fno-unwind-tables -fno-asynchronous-unwind-tables \
    test.c planck.c -lpthread -o planck_test
```

*If you do not need debugging support, you can also compile `planck.c` directly (the `plancknd.c` variant is a debug‑stripped copy – treat it the same way).*

### 2. Run

```bash
./planck_test https://example.com
```

The test program will perform a TLS handshake, send an HTTP GET request, and print the response body.

---

## API Usage

Integrating PlanckTLS into your own C project is straightforward:

```c
#include "planck.h"
#include <stdio.h>

int main() {
    // 1. Initialise the library (seeds the PRNG)
    planck_init();

    // 2. Configure TLS and HTTP versions
    planck_config cfg = {
        .tls_version = PLANCK_TLS_13,  // or PLANCK_TLS_12
        .http_version = PLANCK_HTTP_2  // or PLANCK_HTTP_1
        // .ja3_profile = PLANCK_JA3_CHROME  // optional, see below
    };

    // 3. Connect to the server
    planck_conn *conn = planck_connect("example.com", 443, &cfg);
    if (!conn) {
        fprintf(stderr, "Connection failed!\n");
        return 1;
    }

    // 4. Prepare request headers
    const char *headers[] = {
        "Host: example.com",
        "User-Agent: PlanckTLS/1.0",
        "Accept: */*"
    };

    // 5. Send the request
    uint8_t buffer[32768];
    int bytes_read = planck_request(conn, "GET", "/", headers, 3, NULL, 0, buffer, sizeof(buffer) - 1);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("Response (%d bytes):\n%s\n", bytes_read, buffer);
    } else {
        printf("Request failed.\n");
    }

    // 6. Clean up
    planck_close(conn);
    return 0;
}
```

**Functions**

- `void planck_init(void)` – Initialises the library (must be called once before any connection).
- `planck_conn *planck_connect(const char *host, int port, const planck_config *cfg)` – Opens a TCP connection, performs the TLS handshake, and returns a connection handle.
- `int planck_request(planck_conn *c, const char *method, const char *path, const char **headers, int nheaders, const uint8_t *body, int bodylen, uint8_t *rbuf, int rmax)` – Sends an HTTP request and writes the response body into `rbuf`. Returns the number of bytes written, or -1 on failure.
- `void planck_close(planck_conn *c)` – Closes the connection and frees memory.

**Configuration Struct**

```c
typedef struct {
    int tls_version;   // PLANCK_TLS_13 or PLANCK_TLS_12
    int http_version;  // PLANCK_HTTP_2 or PLANCK_HTTP_1
    int ja3_profile;   // PLANCK_JA3_DEFAULT or PLANCK_JA3_CHROME
} planck_config;
```

---

## JA3 Fingerprinting

PlanckTLS can modify its TLS ClientHello to match different browser fingerprints via the `ja3_profile` field. Currently two presets are available:

- `PLANCK_JA3_DEFAULT` – Minimal set of ciphers and extensions (tiny binary, suitable for most servers).
- `PLANCK_JA3_CHROME` – Cipher and extension list that mimics a recent Chrome browser.

Example:

```c
planck_config cfg = {
    .tls_version  = PLANCK_TLS_13,
    .http_version = PLANCK_HTTP_2,
    .ja3_profile  = PLANCK_JA3_CHROME
};
```

*Note: The Chrome preset increases binary size slightly because of the extended cipher/extension arrays.*

---

## Debug Output

By default, PlanckTLS produces no output to minimise size and I/O. To enable verbose logging (handshake steps, hex dumps, X25519 Montgomery ladder, etc.), compile with `-DPLANCK_DEBUG=1`:

```bash
gcc -Os -DPLANCK_DEBUG=1 -s -ffunction-sections -fdata-sections \
    -Wl,--gc-sections test.c planck.c -lpthread -o planck_debug
./planck_debug https://example.com
```

Debug output is written to `stderr`. Enabling it will increase the binary size because many string literals are compiled in.

> **Alternative**  
> The repository also includes a `plancknd.c` version that has all debug strings removed – you can use it without the `-D` flag if you never need logging.

---

## Minimising Binary Size

PlanckTLS is designed to be compiled with aggressive size‑optimisation flags. The following table explains each flag used in the recommended command:

|              Flag                 |                      Purpose                          |
|-----------------------------------|-------------------------------------------------------|
| `-Os`                             | Optimize for size rather than speed.                  |
| `-s`                              | Strip symbol tables and relocation information.       |
| `-ffunction-sections`             | Place each function in its own section.               |
| `-fdata-sections`                 | Place each variable in its own section.               |
| `-Wl,--gc-sections`               | Linker garbage‑collects unused sections.              |
| `-fno-unwind-tables`              | Remove exception‑handling metadata (unnecessary in C).|
| `-fno-asynchronous-unwind-tables` | Remove async‑unwind tables.                           |

(make sure to do ``upx --ultra-brute --lzma --force <file>`` to get the smallest possible size)

With these flags, stripped binaries are typically **16–24 KB**. Leaving them out may produce binaries of 70 KB or more.

---

## Configuration Options

The `planck_config` struct lets you freely combine TLS and HTTP versions:

```c
// Modern standard
planck_config cfg = { .tls_version = PLANCK_TLS_13, .http_version = PLANCK_HTTP_2 };

// Legacy fallback
planck_config cfg = { .tls_version = PLANCK_TLS_12, .http_version = PLANCK_HTTP_1 };

// Hybrid (modern TLS, HTTP/1.1)
planck_config cfg = { .tls_version = PLANCK_TLS_13, .http_version = PLANCK_HTTP_1 };
```

When HTTP/2 is requested, PlanckTLS will negotiate the protocol via ALPN. If the server does not offer HTTP/2, the connection will fall back to HTTP/1.1.

---

## Limitations & Security Warning

Because PlanckTLS focuses on minimalism and education, it has several important limitations:

1. **No Certificate Validation**  
   PlanckTLS **does not verify** the server’s certificate chain, hostname, expiry, or revocation. It will connect to any server, including those with self‑signed or expired certificates.  
   **Do not use this in production without adding your own certificate pinning or validation layer.**

2. **Client‑Only**  
   This is strictly a client implementation. It cannot act as a TLS server.

3. **Minimal HPACK Decoder**  
   The HTTP/2 implementation can encode headers for requests, but the decoder that reads server response headers is minimal. It correctly extracts the `DATA` (body) payload, but does not fully parse response headers. For many use cases (fetching a body) this is sufficient.

4. **No Session Resumption**  
   PSK (pre‑shared key) session resumption is not implemented. Every connection performs a full handshake.

5. **Single Request per Connection**  
   The current API is designed for one request/response cycle per connection. Multiple requests over the same connection (HTTP/2 multiplexing, HTTP/1.1 keep‑alive) are not yet supported.

---

## Testing

Two example test programs are included:

- `test.c` – Basic HTTPS GET request and response printing.
- `test_multiple.c` – Demonstrates multiple connections / requests (check the source for details).

Compile them the same way as the quick‑start example, substituting `test.c` with `test_multiple.c` when needed.

---

## Maintenance & Status

PlanckTLS is an educational and experimental project. It is actively maintained with the goal of staying tiny, correct, and easy to embed. Contributions and bug reports are welcome.

---

## 📄 License

PlanckTLS is distributed under the MIT License. See [LICENSE](LICENSE) for details.

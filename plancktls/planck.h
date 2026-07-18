#ifndef PLANCK_H
#define PLANCK_H

#include <stdint.h>
#include <stddef.h>

#define PLANCK_TLS_12 12
#define PLANCK_TLS_13 13
#define PLANCK_HTTP_1 1
#define PLANCK_HTTP_2 2
#define PLANCK_JA3_DEFAULT 0
#define PLANCK_JA3_CHROME 1

#define MAX_BUF 32768

typedef struct {
    // Protocol Settings
    int tls_version;      // PLANCK_TLS_12 or PLANCK_TLS_13
    int http_version;     // PLANCK_HTTP_1 or PLANCK_HTTP_2
    int ja3_profile;      // PLANCK_JA3_DEFAULT or PLANCK_JA3_CHROME
    int ignore_cert;      // 1 = Ignore cert errors, 0 = Strict (currently hardcoded to 1 in logic)

    // Timeout Settings (in milliseconds)
    int connect_timeout_ms; // TCP Handshake timeout
    int read_timeout_ms;    // Max time to wait for incoming data
    int write_timeout_ms;   // Max time to wait for socket to accept outgoing data

    // Socket Behavior
    int retry_on_eagain;    // 1 = Use poll() to wait when socket is busy, 0 = Fail immediately
    int max_eagain_retries; // Failsafe limit for poll retries
} planck_config;

#define PLANCK_DEFAULT_CONFIG { \
    .tls_version = PLANCK_TLS_13, \
    .http_version = PLANCK_HTTP_2, \
    .ja3_profile = PLANCK_JA3_CHROME, \
    .ignore_cert = 1, \
    .connect_timeout_ms = 3000, \
    .read_timeout_ms = 5000, \
    .write_timeout_ms = 5000, \
    .retry_on_eagain = 1, \
    .max_eagain_retries = 10 \
}

struct planck_conn {
    int fd;
    planck_config cfg;
    int tls_version;
    int http_version;
    int cipher;
    uint32_t next_stream_id; 
    uint8_t ck[32], sk[32], civ[12], siv[12];
    uint64_t cs, ss;
    uint8_t tx[MAX_BUF];
    uint8_t hs_sk[32], hs_siv[12];
    uint64_t hs_ss;
    uint8_t h2_buf[MAX_BUF];
    int h2_buf_len;
};
#ifndef LOG
#define LOG(fmt, ...) ((void)0)
#endif
// if u want debug, then uncomment the line below, but it will spam a lot of logs, and at above, comment the line to disable the logs
// #ifndef LOG
// #define LOG(fmt, ...) fprintf(stderr, "[LOG] " fmt, ##__VA_ARGS__)
// #endif
typedef struct planck_conn planck_conn;

void planck_init(void);
planck_conn *planck_connect(const char *host, int port, const planck_config *cfg);
int planck_request(planck_conn *c, const char *method, const char *path, const char **hdrs, int nhdrs, const uint8_t *body, int bodylen, uint8_t *rbuf, int rmax);
void planck_close(planck_conn *c);

#endif

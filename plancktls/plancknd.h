#ifndef PLANCKND_H
#define PLANCKND_H
#include <stdint.h>
#include <stddef.h>

#define PLANCK_TLS_13 13
#define PLANCK_TLS_12 12
#define PLANCK_HTTP_2 2
#define PLANCK_HTTP_1 1

typedef struct {
    int tls_version;
    int http_version;
} planck_config;

typedef struct planck_conn planck_conn;

void planck_init(void);
planck_conn *planck_connect(const char *host, int port, const planck_config *cfg);
int planck_request(planck_conn *c, const char *method, const char *path,
                   const char **hdrs, int nhdrs,
                   const uint8_t *body, int bodylen,
                   uint8_t *rbuf, int rmax);
void planck_close(planck_conn *c);
#endif
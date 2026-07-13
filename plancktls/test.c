#include "planck.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void parse_url(const char *input, char *host, int *port, char *path, int *use_tls) {
    *use_tls = 1;
    *port = 443;
    strcpy(path, "/");

    const char *p = input;

    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        *use_tls = 1;
        *port = 443;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *use_tls = 0;
        *port = 80;
    }

    const char *host_end = p;
    while (*host_end && *host_end != ':' && *host_end != '/') host_end++;

    size_t host_len = host_end - p;
    if (host_len >= 256) host_len = 255;
    memcpy(host, p, host_len);
    host[host_len] = '\0';

    if (*host_end == ':') {
        *port = atoi(host_end + 1);
        const char *after_port = host_end + 1;
        while (*after_port && *after_port != '/') after_port++;
        if (*after_port == '/') strcpy(path, after_port);
    } else if (*host_end == '/') {
        strcpy(path, host_end);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, " %s <url> [port]\n", argv[0]);
        fprintf(stderr, "  url:  https://balls.com/path, saygex.com, or fbi.com:8080/path\n");
        return 1;
    }

    char host[256];
    char path[1024];
    int port;
    int use_tls;

    parse_url(argv[1], host, &port, path, &use_tls);

    if (argc >= 3) {
        port = atoi(argv[2]);
    }

    if (!use_tls) {
        fprintf(stderr, "Plain HTTP not supported by PlanckTLS\n");
        return 1;
    }

    printf("comming to %s:%d%s ( i see you )\n", host, port, path);

    planck_init();

    planck_config cfg = {
        .tls_version = PLANCK_TLS_13,
        .http_version = PLANCK_HTTP_2
    };

    planck_conn *c = planck_connect(host, port, &cfg);
    if (c) {
        char host_hdr[512];
        snprintf(host_hdr, sizeof(host_hdr), "Host: %s", host);

        const char *hdrs[] = {
            host_hdr,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            "Accept: */*"
        };
        uint8_t buf[32768];
        int n = planck_request(c, "GET", path, hdrs, 3, NULL, 0, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = 0;
            printf("Response (%d bytes):\n", n);
            for(int i=0; i<n; i++) {
                if(buf[i] == 0) printf(".");
                else if(buf[i] < 32 || buf[i] > 126) printf("?");
                else printf("%c", buf[i]);
            }
            printf("\n");
        } else {
            printf("Request failed\n");
        }
        planck_close(c);
    } else {
        printf("Connection failed\n");
    }

    return 0;
}
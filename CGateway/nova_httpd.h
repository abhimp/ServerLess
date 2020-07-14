#ifndef __NOVA_HTTPD_H__
#define __NOVA_HTTPD_H__

#define EIGHT_KB 8192
#define MAX_HEADERS 50

#include "picohttpparser.h"

struct _http_request_header_ {
    int sockfd;
    char *method, *path;
    size_t methodLen, pathLen;
    int version;
    char *queryString;
    size_t queryStringLen;
    struct phr_header headers[MAX_HEADERS];
    size_t headerLen;
    char buf[EIGHT_KB]; //maximum header length allowed in apache
    size_t buflen;
};


typedef struct _http_request_header_ nova_request_connect;

enum nova_route_type {
    NOVA_ROUTE_FILE,
    NOVA_ROUTE_CGI,
    NOVA_ROUTE_NCGI, //nova cgi
    NOVA_ROUTE_FUNC
};


typedef void (*nova_route_handler)(const char *path, const char *method, const void *headers);
void novaHandle(nova_request_connect *conn);
int novaRegisterHandler(char *route, char *method, enum nova_route_type type, char *cdir, nova_route_handler handler);
char *novaGetHttpRequestHeader(const void *headers, char *name);
int novaGetHttpRequestHeaderCnt(const void *headers);
int novaGetHttpRequestHeaderValue(const void *headers, int id, const char **name, const char **val);

void novaHttpdServer(char *port);

#endif

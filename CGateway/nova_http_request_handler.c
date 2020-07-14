#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nova_httpd.h"
#include "nova_http_request_handler.h"

struct nova_handler_enrty {
    enum nova_route_type type;
    int routelen;
    char *route;
    char *method;
    char *cdir; //required in case of cgi,
    nova_route_handler handler;
};


struct nova_handler_enrty *handlerRegistry = NULL;
int handleRegistryCnt = 0;
int handleRegistryCapa = 0;

static void sendError(int num, char *msg, int sockfd) {
    char buf[100];
    sprintf(buf, "HTTP/1.0 %d %s\r\n\r\n", num, msg);
    send(sockfd, buf, strlen(buf), 0);
    cleanUpRecvBuf(sockfd);
}

nova_request_connect *dereferenceHttpConn(const void *headers) {
    return (nova_request_connect *)(((char *) headers) - (char *)(&((nova_request_connect *)NULL)->headers));
}

char *novaGetHttpRequestHeader(const void *headers, char *name) {
    nova_request_connect *conn;
    conn = (nova_request_connect *)(((char *) headers) - (char *)(&((nova_request_connect *)NULL)->headers));
    return NULL;
}

int novaGetHttpRequestHeaderCnt(const void *headers) {
    nova_request_connect *conn = dereferenceHttpConn(headers);
    return (int)conn->headerLen;
}
int novaGetHttpRequestHeaderValue(const void *headers, int id, const char **name, const char **val) {
    nova_request_connect *conn = dereferenceHttpConn(headers);
    *name = NULL;
    *val = NULL;
    if(id >= conn->headerLen) {
        return 0;
    }
    *name = conn->headers[id].name;
    *val = conn->headers[id].value;
    return 1;
}

static void handleWithFunctionHandler(struct nova_handler_enrty *entry, nova_request_connect *conn) {
    pid_t pid;
    pid = fork();
    if(pid < 0) {
        perror("fork");
        exit(0);
    }

    if(pid) { // parent
        return;
    }

    readNParseHeaders(conn);
    conn->path[conn->pathLen] = 0;
    conn->method[conn->methodLen] = 0;

    dup2(conn->sockfd, STDOUT_FILENO);
    close(conn->sockfd);
    printf("HTTP/1.0 200 OK\r\n");

    entry->handler(conn->path, conn->method, &conn->headers);

    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);

    exit(0);
}

static void handleWithHandler(struct nova_handler_enrty *entry, nova_request_connect *conn) {
    switch(entry->type) {
        case NOVA_ROUTE_FILE:
            break;
        case NOVA_ROUTE_CGI:
            break;
        case NOVA_ROUTE_NCGI:
            break;
        case NOVA_ROUTE_FUNC:
            handleWithFunctionHandler(entry, conn);
            return;
            break;
    }
    sendError(407, "Error", conn->sockfd);
}

void novaHandle(nova_request_connect *conn) {
    const char *path = conn->path;
    const int pathlen = (int) conn->pathLen;

    if(path[0] != '/'){
        sendError(502, "Error", conn->sockfd);
        return;
    }

    int i;
    struct nova_handler_enrty *entry = NULL;
    for(i = 0; i < handleRegistryCnt; i++) {
        struct nova_handler_enrty *ptr = handlerRegistry + i;
        if(strncmp(conn->path, ptr->route, ptr->routelen) == 0 &&
                (!ptr->method || strncmp(ptr->method, conn->method, conn->methodLen) == 0)) {
            if(!entry || ptr->routelen > entry->routelen) {
                entry = ptr;
            }
        }
    }
    if(entry) {
            handleWithHandler(entry, conn);
            return;
    }
    sendError(404, "Error", conn->sockfd);
}

int novaRegisterHandler(char *route, char *method, enum nova_route_type type, char *cdir, nova_route_handler handler) {
    if(handleRegistryCapa == handleRegistryCnt) {
        handlerRegistry = realloc(handlerRegistry, (handleRegistryCapa + 32) * sizeof(struct nova_handler_enrty));
        handleRegistryCapa += 32;
    }
    handlerRegistry[handleRegistryCnt] = (struct nova_handler_enrty) {
                                            .type = type,
                                            .routelen = strlen(route),
                                            .route = route,
                                            .method = method,
                                            .cdir = cdir,
                                            .handler = handler
                                        };
    handleRegistryCnt ++;
    return 0;
}

/*
 * nova_httpd_util.c
 *
 *  Created on: Jul 16, 2020
 *      Author: abhijit
 */



#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define _GNU_SOURCE
#define _USE_GNU
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include "nova_httpd.h"
#include "nova_http_request_handler.h"




struct nova_handler_enrty *handlerRegistry = NULL;
int handleRegistryCnt = 0;
int handleRegistryCapa = 0;

void novaNcgiSendError(nova_httpd_request *conn, int status) {
     char buf[100];
     sprintf(buf, "HTTP/1.0 %s\r\n\r\n", HTTP_RESPONSE_STATUS[status]);
     send(conn->sockfd, buf, strlen(buf), 0);
    cleanUpRecvBuf(conn->sockfd);
}

static struct nova_control_socket *handleWithFunctionHandler(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    pid_t pid;
    pid = fork();
    if(pid < 0) {
        perror("fork");
        exit(0);
    }

    if(pid) { // parent
        return NULL;
    }

    novaReadNParseHeaders(conn);
    conn->method[conn->methodLen] = 0;

    dup2(conn->sockfd, STDOUT_FILENO);
    close(conn->sockfd);
    printf("HTTP/1.0 200 OK\r\n");

    entry->handler(conn->path, conn->method, conn);

    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);

    exit(0);
}


static int ncgi_unique_id = 5001;
//this need to run before the fork. However, uid is needed mostly after the fork.
int novaNcgiGetNewUid() {
    int uid = ncgi_unique_id+1;
    ncgi_unique_id ++;
    return uid;
}

//this function need to after the fork.
void novaNcgiSetupChildExecution(struct nova_handler_enrty *entry, nova_httpd_request *conn, char *cgiPath, char *cgiName, int uid) {
#define SEND_ERROR(st, num) { \
        perror(st " at " NOVA_FILE_N_LINE); \
        novaNcgiSendError(conn, num); \
        exit(1); \
    }
    if(!realpath(entry->cdir, cgiPath))
        SEND_ERROR("realpath: ", 500);

    printf("cgiPath: %s\n", cgiPath);
    int pathlen = strlen(cgiPath);
    if(cgiPath[pathlen - 1] != '/') {
        cgiPath[pathlen] = '/';
        cgiPath[++pathlen] = 0;
    }
    if(entry->map) { //FIXME make the search faster
        char *exe = conn->path + entry->routelen;
        char *slash = strchr(exe, '/');
        if(slash)
            *slash = 0;
        char found = 0;
        int i;
        for(i = 0; entry->map[i][0]; i++) {
            if(strcmp(entry->map[i][0], exe) == 0) {
                strcpy(cgiPath + pathlen, entry->map[i][1]);
                found = 1;
                break;
            }
        }
        if(slash)
            *slash = '/';
        if(!found)
            SEND_ERROR("Not Found", 407);
    }
    else {
        strcpy(cgiPath + pathlen, conn->path + entry->routelen);
    }

    strcpy(cgiName, conn->path + entry->routelen);
    if(access(cgiPath, X_OK) < 0) {
        strcat(cgiPath, ".fn");
        if(access(cgiPath, X_OK))
            SEND_ERROR("access", 403);
    }

//typedef void (*nova_child_setup)(const char *path, const char *method, const char *exe, const void *headers);
    if(entry->childsetter) {
        if(entry->childsetter(conn->path, conn->method, cgiPath, conn, uid) < 0){
            novaNcgiSendError(conn, 500);
            exit(1);
        }
    }
#undef SEND_ERROR
}


static struct nova_control_socket *handleWithHandler(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    switch(entry->type) {
        case NOVA_ROUTE_FILE:
            return NULL;
        case NOVA_ROUTE_NCGIS:
            return novaHandleWithNCGIS(entry, conn); //need more effort needed or our library need to be added
        case NOVA_ROUTE_NCGIM:
            return novaHandleWithNCGIM(entry, conn);
        case NOVA_ROUTE_FUNC:
            return handleWithFunctionHandler(entry, conn);
    }
    novaNcgiSendError(conn, 404);
    return NULL;
}

struct nova_control_socket *novaHandle(nova_httpd_request *conn) {

    conn->queryString = memchr(conn->path, '?', conn->pathLen);
    if (conn->queryString) {
        conn->queryString++;
        conn->queryStringLen = conn->path + conn->pathLen - conn->queryString;
        conn->pathLen = conn->queryString - conn->path;
        conn->queryString[conn->queryStringLen] = 0;
    }
    // perform a url decoding for the path
    conn->pathLen = novaHttpdPercentDecode(conn->path, conn->pathLen);
    conn->path[conn->pathLen] = 0;
    conn->method[conn->methodLen] = 0;

    const char *path = conn->path;

    if(path[0] != '/'){
        novaNcgiSendError(conn, 502);
        return NULL;
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
            return handleWithHandler(entry, conn);
    }
    novaNcgiSendError(conn, 404);
    return NULL;
}

void handleControlConnection(struct nova_control_socket *ptr) {
    printf("ptr");
    switch(ptr->routeType) {
        case NOVA_ROUTE_FILE:
            return;
        case NOVA_ROUTE_NCGIS:
            return; //need more effort needed or our library need to be added
        case NOVA_ROUTE_NCGIM:
            novaHandleNCGIControlSocket(ptr);
            return;
        case NOVA_ROUTE_FUNC:
            return;
    }
}

int novaRegisterHandler(char *route, char *method, enum nova_route_type type, char *cdir, nova_route_handler handler, nova_child_setup childsetter) {
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
                                            .handler = handler,
                                            .childsetter = childsetter
                                        };
    handleRegistryCnt ++;
    return 0;
}


int novaRegisterNcgimHandler(char *route, char *method, char *cdir, char const *(*map)[2], nova_child_setup childsetter) {
    if(handleRegistryCapa == handleRegistryCnt) {
        handlerRegistry = realloc(handlerRegistry, (handleRegistryCapa + 32) * sizeof(struct nova_handler_enrty));
        handleRegistryCapa += 32;
    }
    handlerRegistry[handleRegistryCnt] = (struct nova_handler_enrty) {
                                            .type = NOVA_ROUTE_NCGIM,
                                            .routelen = strlen(route),
                                            .route = route,
                                            .method = method,
                                            .cdir = cdir,
//                                            .handler = handler,
                                            .map = map,
                                            .childsetter = childsetter
                                        };
    handleRegistryCnt ++;
    return 0;
}

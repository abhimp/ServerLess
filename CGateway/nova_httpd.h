#ifndef __NOVA_HTTPD_H__
#define __NOVA_HTTPD_H__

#include <stdio.h>


//#include "picohttpparser.h"
#include "nova_http_status_code.h"
#include "nova_httpd_util.h"


enum nova_route_type {
    NOVA_ROUTE_FILE,
    NOVA_ROUTE_NCGIS, //nova cgi single run
    NOVA_ROUTE_NCGIM, //nova cgi multiple run
    NOVA_ROUTE_FUNC
};

struct nova_control_socket {
    enum _epoll_type socktype;
    int sockfd;
    enum nova_route_type routeType;
    pid_t childpid;
    char *script;
    char serving;
    struct nova_control_socket *next, **prev;
};



typedef void (*nova_route_handler)(const char *path, const char *method, const void *headers);
struct nova_control_socket *novaHandle(nova_httpd_request *conn);
int novaRegisterHandler(char *route, char *method, enum nova_route_type type, char *cdir, nova_route_handler handler);

void handleControlConnection(struct nova_control_socket *ptr);


void novaHttpdServer(char *port);


#define CLEAN_UP_ZOMBIES while(1) { \
            int status; \
            pid_t childpid = waitpid(0, &status, WNOHANG); \
            if(childpid <= 0) break; \
        }


#endif

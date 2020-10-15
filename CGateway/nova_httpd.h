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


#define NOVA_STR1(x, y) # y
#define NOVA_STR(X) NOVA_STR1("", X)
#define NOVA_STR_LINE() NOVA_STR(__LINE__)
#define NOVA_FILE_N_LINE __FILE__ ":" NOVA_STR_LINE()


typedef void (*nova_route_handler)(const char *path, const char *method, const void *headers);
typedef int (*nova_child_setup)(const char *path, const char *method, const char *exe, const void *headers, const int uid); //to setup child
typedef char const *nova_handler_map[][2] ;

struct nova_control_socket *novaHandle(nova_httpd_request *conn);
int novaRegisterHandler(char *route, char *method, enum nova_route_type type, char *cdir, nova_route_handler handler, nova_child_setup childsetter);
int novaRegisterNcgimHandler(char *route, char *method, char *cdir, char const *(*map)[2], nova_child_setup childsetter);

void handleControlConnection(struct nova_control_socket *ptr);


void novaHttpdServer(char *port);





#endif

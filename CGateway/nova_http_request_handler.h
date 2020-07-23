#ifndef __NOVA_HTTP_REQUEST_HANDLER_H__
#define __NOVA_HTTP_REQUEST_HANDLER_H__

#include "nova_httpd.h"

struct nova_handler_enrty {
    enum nova_route_type type;
    int routelen;
    char *route;
    char *method;
    char *cdir; //required in case of cgi,
    nova_route_handler handler;
    nova_child_setup childsetter;
};



void novaNcgiSendError(nova_httpd_request *conn, int status);
int novaNcgiGetNewUid();
void novaNcgiSetupChildExecution(struct nova_handler_enrty *entry, nova_httpd_request *conn, char *cgiPath, int uid);

struct nova_control_socket *novaHandleWithNCGIS(struct nova_handler_enrty *entry, nova_httpd_request *conn);

struct nova_control_socket *novaHandleWithNCGIM(struct nova_handler_enrty *entry, nova_httpd_request *conn);
void novaHandleNCGIControlSocket(struct nova_control_socket *ptr);

#endif

/*
 * nova_http_ncgis_handler.c
 *
 *  Created on: Jul 23, 2020
 *      Author: abhijit
 */

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>


#include "nova_http_request_handler.h"

#define SEND_500_ERROR(x) { \
    perror(x " at " NOVA_FILE_N_LINE); \
    novaNcgiSendError(conn, 500); \
    exit(0); \
}
static void setupEnvironmentVariable(nova_httpd_request *conn, char ***env) {
#define ADD2ENV(x, y) { \
    if(envCapa - envLen < 2) { \
        if(!(*env = realloc(*env, (envCapa + 16)*sizeof(char *)))) \
            SEND_500_ERROR("realloc"); \
        envCapa += 12; \
    } \
    (*env)[envLen] = malloc(strlen(x) + strlen(y) + 2); /* `=` and `\0` */ \
    if(!(*env)[envLen]) { \
        SEND_500_ERROR("malloc"); \
    } \
    strcpy((*env)[envLen], x); \
    strcat((*env)[envLen], "="); \
    strcat((*env)[envLen], y); \
    (*env)[++envLen] = 0; \
}

    int i;
    int envLen, envCapa;
    envLen = envCapa = 0;
    for(i = 0; i < conn->headerLen; i++) {
#define COMP_N_ADD(x, y) } else if (!strcasecmp(conn->headers[i].name, y)) { \
    ADD2ENV(x, conn->headers[i].value)
        if(0) {
        COMP_N_ADD("AUTH_TYPE", "auth-scheme");
        COMP_N_ADD("CONTENT_LENGTH", "content-length");
        COMP_N_ADD("CONTENT_TYPE", "content-type");
//         COMP_N_ADD("HTTP_COOKIE", "Cookie");
#undef COMP_N_ADD
        } else {
            char newk[100] = "HTTP_";
            {
                const char *in = conn->headers[i].name;
                char *out = newk + 5;
                while(*in && (out - newk) < (sizeof(newk) - 1)) {
                    if(*in == '-')
                        *out = '_';
                    else if (*in == '=')
                        *out = '_';
                    else
                        *out = toupper(*in);
                    in++;
                    out++;
                }
                *out = 0;
            }
            ADD2ENV(newk, conn->headers[i].value);
        }
    }

    struct sockaddr_storage localAddr = {0};
    struct sockaddr_storage remoteAddr = {0};
    socklen_t sockaddrlen = sizeof(localAddr);

    if(getsockname(conn->sockfd, (struct sockaddr*)(&localAddr), &sockaddrlen) < 0) {
        SEND_500_ERROR("getsockname");
    }

    sockaddrlen = sizeof(remoteAddr);
    if(getpeername(conn->sockfd, (struct sockaddr*)(&remoteAddr), &sockaddrlen) < 0) {
        SEND_500_ERROR("getpeername");
    }

    char remoteIp[INET6_ADDRSTRLEN] = {0};
    char localIp[INET6_ADDRSTRLEN] = {0};
    char localPort[10], remotePort[10];
    if(remoteAddr.ss_family == AF_INET6 && localAddr.ss_family == AF_INET6) {
        if(!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&remoteAddr)->sin6_addr, remoteIp, INET6_ADDRSTRLEN) ||
                !inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&localAddr)->sin6_addr, localIp, INET6_ADDRSTRLEN)) {
            SEND_500_ERROR("inet_ntop AF_INET6");
        }
        sprintf(remotePort, "%d", ntohs(((struct sockaddr_in6 *)&remoteAddr)->sin6_port));
        sprintf(localPort, "%d", ntohs(((struct sockaddr_in6 *)&localAddr)->sin6_port));
    } else if(remoteAddr.ss_family == AF_INET && localAddr.ss_family == AF_INET) {
        if(!inet_ntop(AF_INET, &((struct sockaddr_in *)&remoteAddr)->sin_addr, remoteIp, INET6_ADDRSTRLEN) ||
                !inet_ntop(AF_INET, &((struct sockaddr_in *)&localAddr)->sin_addr, localIp, INET6_ADDRSTRLEN)) {
            SEND_500_ERROR("inet_ntop AF_INET");
        }
        sprintf(remotePort, "%d", ntohs(((struct sockaddr_in *)&remoteAddr)->sin_port));
        sprintf(localPort, "%d", ntohs(((struct sockaddr_in *)&localAddr)->sin_port));
    } else {
        novaNcgiSendError(conn, 500);
        exit(0);
    }


    ADD2ENV("GATEWAY_INTERFACE", "CGI/1.1");
    ADD2ENV("HTTP_HOST", "MAGIC_NOVA_GATEWAY");
    ADD2ENV("PATH_INFO", conn->path);
    ADD2ENV("PATH_TRANSLATED", conn->path);

    if(conn->queryString)
        ADD2ENV("QUERY_STRING", conn->queryString);

    ADD2ENV("REMOTE_ADDR", remoteIp);
    ADD2ENV("REMOTE_HOST", remoteIp);
//     ADD2ENV("REMOTE_IDENT", ); //NOT required at this moment
    ADD2ENV("REQUEST_METHOD", conn->method);
    ADD2ENV("SCRIPT_NAME", conn->path);
    ADD2ENV("SERVER_NAME", "MAGIC_NOVA_GATEWAY"); //hostname
    ADD2ENV("SERVER_PORT", localPort);
    ADD2ENV("SERVER_PROTOCOL", "HTTP/1.0");
    ADD2ENV("SERVER_SOFTWARE", "nova_cgi_gateway");
    //add from current paths
    char *val;
    if((val = getenv("PATH")))
            ADD2ENV("PATH", val);
#undef ADD2ENV
}

static void executeCgi(struct nova_handler_enrty *entry, nova_httpd_request *conn, char *cgiPath) {
//    char *cgiPath = conn->path + entry->routelen;

//     char *const (*env)[2]; // a pointer to array of length 2 of pointer to const char
    char **env = NULL;

    setupEnvironmentVariable(conn, &env);

    fflush(stdout);
    if(dup2(conn->sockfd, STDOUT_FILENO) < 0) {
        SEND_500_ERROR("getcwd");
    }
    if(dup2(conn->sockfd, STDIN_FILENO) < 0) {
        SEND_500_ERROR("getcwd");
    }
    close(conn->sockfd);
    if(execle(cgiPath, cgiPath, NULL, env) < 0) {
        SEND_500_ERROR("execle");
    }
}
#undef SEND_500_ERROR

struct nova_control_socket *novaHandleWithNCGIS(struct nova_handler_enrty *entry, nova_httpd_request *conn) {

    int uid = novaNcgiGetNewUid();
    //add option to set close on exec
    pid_t pid = fork();
    if(pid < 0) {
        perror("fork");
        novaNcgiSendError(conn, 500);
        return NULL;
    }
    if(pid) return NULL;

    char cgiPath[PATH_MAX];

    novaNcgiSetupChildExecution(entry, conn, cgiPath, uid);

    novaReadNParseHeaders(conn);

    printf("current pid: %d\n", getpid());

    executeCgi(entry, conn, cgiPath);

    exit(0);
}

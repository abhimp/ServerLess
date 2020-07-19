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
#include <sys/socket.h>
#include <fcntl.h>
#include <assert.h>

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

void sendError(nova_httpd_request *conn, int status) {
//     nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
//    novaStartResponseHeader(conn->headers, status);
//    novaEndResponseHeader(conn->headers);
//     char buf[100];
//     sprintf(buf, "HTTP/1.0 %s\r\n\r\n", HTTP_RESPONSE_STATUS[num]);
//     send(sockfd, buf, strlen(buf), 0);
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



#define SEND_500_ERROR(x) { \
    perror(x); \
    sendError(conn, 500); \
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
        sendError(conn, 500);
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

static void executeCgi(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    char *cgiPath = conn->path + entry->routelen;

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
    //Finally run it
    cgiPath -= 2; //extreamly bad hack to avoid memory allocation
    cgiPath[0] = '.';
    cgiPath[1] = '/';
    if(execle(cgiPath, cgiPath, NULL, env) < 0) {
        SEND_500_ERROR("execle");
    }
}
#undef SEND_500_ERROR

// static int execAfterClone(void *arg) {
//     void **buf = (void **) arg;
//     struct nova_handler_enrty *entry;
//     nova_request_connect *conn;
//     entry = buf[0];
//     conn = buf[1];
//     executeCgi(entry, conn);
//     return 0;
// }
// //
// static void cloneExec(struct nova_handler_enrty *entry, nova_request_connect *conn) {
//     const int STACK_SIZE = 65536;
//     char *stack = malloc(STACK_SIZE);
//     void *buf[2] = {entry, conn};
//     pid_t tid;
//     if ((tid = clone(execAfterClone, stack + STACK_SIZE - 1, CLONE_SIGHAND|CLONE_FS|CLONE_VM|CLONE_FILES|CLONE_THREAD, buf)) == -1) {
//         perror("clone");
//         exit(1);
//     }
// //
//     int status;
//     if (waitpid(tid, &status, __WCLONE) == -1) {
//         perror("wait");
//         exit(1);
//     }
//     free(stack);
// }

static void setupAndRunCgi(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    char *cgiPath = conn->path + entry->routelen;
    char cwd[200];
    if(!getcwd(cwd, sizeof(cwd))) {
        perror("getcwd");
        sendError(conn, 500);
        return;
    }

    if(!entry->cdir) {
        sendError(conn, 500);
        return;
    }

    if(chdir(entry->cdir) < 0){
        perror("chdir");
        sendError(conn, 404);
        return;
    }

    if(access(cgiPath, X_OK) < 0) {
        perror("access");
        sendError(conn, 403);
        return;
    }

    novaReadNParseHeaders(conn);

    printf("current pid: %d\n", getpid());

//     cloneExec(entry, conn);
    executeCgi(entry, conn);

    exit(0);
}

static struct nova_control_socket *handleWithCGI(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    //add option to set close on exec
    pid_t pid = fork();
    if(pid < 0) {
        perror("fork");
        sendError(conn, 500);
        return NULL;
    }
    if(pid) return NULL;
    setupAndRunCgi(entry, conn);
    exit(0);
}


struct _nova_channel {
    struct nova_control_socket *working, *worker; //linked list;
    int numWorking;
    int numPending;
    char *scriptName;
};

void addition(struct nova_control_socket **head, struct nova_control_socket *ele) {
    assert(head && ele);
    ele->prev = head;
    ele->next = *head;
    if(*head)
        (*head)->prev = &ele->next;
    *head = ele;
}

void deletion(struct nova_control_socket *ele) {
    assert(ele);
    *ele->prev = ele->next;
    if(ele->next)
        ele->next->prev = ele->prev;
    ele->next = NULL;
    ele->prev = NULL;
}

static int novaChannelComp(const struct _nova_channel *ptr1, const struct _nova_channel *ptr2) {
    if(!ptr1)
        return -1;
    if(!ptr2)
        return 1;
    return strcmp(ptr1->scriptName, ptr2->scriptName);
}

static struct nova_control_socket *ncgiGetWorker(struct _nova_channel *chan) {
    if(!chan->worker)
        return NULL;
    struct nova_control_socket *worker = chan->worker;
    chan->worker = chan->worker->next;
    worker->next = chan->working;
    chan->working = worker;
    chan->numPending --;
    chan->numWorking ++;
    return worker;
}


static struct nova_control_socket *ncgiCreateWorker(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
#define SEND_500_ERROR(st) { \
        perror(st); \
        sendError(conn, 500); \
        return NULL; \
    }

    int sockvector[2];
    int localfd, remotefd;
    if(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockvector) < 0) {
        SEND_500_ERROR("socketpair");
    }

    remotefd = sockvector[0];
    localfd = sockvector[1];

//    printf("localfd: %d remotefd: %d", localfd, remotefd);

    if (fcntl(localfd, F_SETFD, FD_CLOEXEC) == -1 || fcntl(localfd, F_SETFL, O_NONBLOCK) == -1) { //making child process wont have access to it
        close(localfd);
        close(localfd);
        SEND_500_ERROR("fcntl");
    }

    pid_t pid = fork();
    if(pid < 0) {
        perror("fork");
        sendError(conn, 500);
    }
    if(pid) {
        close(remotefd);
//        printf("pid: %d\n", pid);
        struct nova_control_socket *worker = malloc(sizeof(struct nova_control_socket));
        *worker = (struct nova_control_socket) {
            .socktype = NOVA_SOCK_TYPE_CTL,
            .sockfd = localfd,
            .childpid = pid,
            .serving = 0,
            .routeType = NOVA_ROUTE_NCGIM
        };
        return worker;
    }

#undef SEND_500_ERROR

    char *cgiPath = conn->path + entry->routelen;
    char cwd[200];
    if(!getcwd(cwd, sizeof(cwd))) {
        perror("getcwd");
        sendError(conn, 500);
        exit(1);
    }

    if(!entry->cdir) {
        sendError(conn, 404);
        exit(1);
    }

    if(chdir(entry->cdir) < 0){
        perror("chdir");
        sendError(conn, 404);
        exit(1);
    }

    if(access(cgiPath, X_OK) < 0) {
        perror("access");
        sendError(conn, 403);
        exit(1);
    }

    localfd = dup2(remotefd, 4); //we want local-fd to be 4
    if(localfd < 0){
        perror("dup");
        sendError(conn, 500);
        exit(1);
    }

    close(remotefd);
//    printf("Local fd: %d\n", localfd);

    cgiPath -= 2; //extreamly bad hack to avoid memory allocation
    cgiPath[0] = '.';
    cgiPath[1] = '/';

    char FD[20];
    snprintf(FD, 20, "NCGI_FD=%d", localfd);
    char *env[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            FD,
            NULL
    };

    if(execle(cgiPath, cgiPath, NULL, env) < 0) {
        perror("execle");
    }

    exit(0);
}

struct nova_map *novaNCGIMap = NULL;
static struct nova_control_socket *handleWithNCGI(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    if(!novaNCGIMap) {
        novaNCGIMap = novaInitMap((int (*)(const void *, const void *))novaChannelComp);
    }

    struct _nova_channel *channel, key;
    key = (struct _nova_channel){
        .scriptName = conn->path
    };
    channel = (struct _nova_channel *)novaSearch(novaNCGIMap, &key);
    if(!channel) {
        channel = malloc(sizeof(struct _nova_channel) + strlen(conn->path)+1); //do not wants to make two calls
        *channel = (struct _nova_channel) {
            .scriptName = ((char *)channel) + sizeof(struct _nova_channel)
        };
        strcpy(channel->scriptName, conn->path);
        novaAddToMap(novaNCGIMap, channel);
    }
    struct nova_control_socket *worker, *ret = NULL;
    worker = ncgiGetWorker(channel);
    if(!worker) {
        worker = ncgiCreateWorker(entry, conn);
        ret = worker;
        worker->script = channel->scriptName;
        addition(&channel->working, worker);
        channel->numWorking ++;
    }
//    printf("available workers:");
//    for(struct nova_control_socket *tmp = channel->worker; tmp; tmp=tmp->next) printf(" %d", tmp->childpid);
//    for(struct nova_control_socket *tmp = channel->working; tmp; tmp=tmp->next) printf(" %d", tmp->childpid);
//    printf("\n");

    // SETUP is complete. send the fd and close it
    int sent = novaSendFd(worker->sockfd, conn->sockfd, conn->buf, conn->buflen);

    if(sent <= 0) { //socket closed, possibly the process
        //TODO cleanup
        kill(worker->childpid, SIGTERM); //just a precaution
        close(worker->sockfd);
        ret = NULL;
        deletion(worker);
        channel->numWorking --;
        printf("previously assigned worker:%d seems dead\n", worker->childpid);

        return handleWithNCGI(entry, conn);
    }
    printf("Worker assinged: %d\n", worker->childpid);
    return ret;
}

static void handleNCGIControl(struct nova_control_socket *ptr) {
    char buf[100];
    char removeOnly = 0;
    if(recv(ptr->sockfd, buf, 100, 0) <= 0) {
        kill(ptr->childpid, SIGTERM);
        close(ptr->sockfd);
        removeOnly = 1;
    }

    struct _nova_channel *channel, key;
    key = (struct _nova_channel){
        .scriptName = ptr->script
    };
    channel = (struct _nova_channel *)novaSearch(novaNCGIMap, &key);
    assert(channel);

    deletion(ptr);
    channel->numWorking --;

    printf("Worker reported back: %d\n", ptr->childpid);

    if(removeOnly) {
        free(ptr);
        return;
    }
    addition(&channel->worker, ptr);
    channel->numPending ++;
//    ptr->next = channel->worker;
//    channel->worker = ptr;
}

static struct nova_control_socket *handleWithHandler(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    switch(entry->type) {
        case NOVA_ROUTE_FILE:
            return NULL;
        case NOVA_ROUTE_NCGIS:
            return handleWithCGI(entry, conn); //need more effort needed or our library need to be added
        case NOVA_ROUTE_NCGIM:
            return handleWithNCGI(entry, conn);
        case NOVA_ROUTE_FUNC:
            return handleWithFunctionHandler(entry, conn);
    }
    sendError(conn, 404);
    return NULL;
}

struct nova_control_socket *novaHandle(nova_httpd_request *conn) {
//    char altBuf[EIGHT_KB]; //this this stack memory.

//==============================================================
//    memcpy(altBuf, conn->buf, conn->buflen);
//    conn->path = altBuf + (conn->path - conn->buf);
//    conn->method = altBuf + (conn->method - conn->buf);
//==============================================================

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
        sendError(conn, 502);
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
    sendError(conn, 404);
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
            handleNCGIControl(ptr);
            return;
        case NOVA_ROUTE_FUNC:
            return;
    }
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

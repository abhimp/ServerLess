/*
 * nova_httpd_ncgim_handler.c
 *
 *  Created on: Jul 23, 2020
 *      Author: abhijit
 */

#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>


#include "nova_http_request_handler.h"


struct _nova_channel {
    struct nova_control_socket *working, *worker; //linked list;
    int numWorking;
    int numPending;
    char *scriptName;
};

static void addition(struct nova_control_socket **head, struct nova_control_socket *ele) {
    assert(head && ele);
    ele->prev = head;
    ele->next = *head;
    if(*head)
        (*head)->prev = &ele->next;
    *head = ele;
}

static void deletion(struct nova_control_socket *ele) {
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
        perror(st " at " NOVA_FILE_N_LINE); \
        novaNcgiSendError(conn, 500); \
        return NULL; \
    }

    int sockvector[2];
    int localfd, remotefd;
    if(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockvector) < 0) {
        SEND_500_ERROR("socketpair");
    }

    remotefd = sockvector[0];
    localfd = sockvector[1];
    int uid = novaNcgiGetNewUid();

//    printf("localfd: %d remotefd: %d", localfd, remotefd);

    if (fcntl(localfd, F_SETFD, FD_CLOEXEC) == -1 || fcntl(localfd, F_SETFL, O_NONBLOCK) == -1) { //making child process wont have access to it
        close(localfd);
        close(remotefd);
        SEND_500_ERROR("fcntl");
    }

    pid_t pid = fork();
    if(pid < 0) {
        perror("fork");
        novaNcgiSendError(conn, 500);
    }
    if(pid) {
        close(remotefd);
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
#define SEND_ERROR(st, num) { \
        perror(st " at " NOVA_FILE_N_LINE); \
        novaNcgiSendError(conn, num); \
        exit(1); \
    }

    localfd = dup2(remotefd, 4); //we want local-fd to be 4
    if(localfd < 0){
        perror("dup");
        novaNcgiSendError(conn, 500);
        exit(1);
    }

    close(remotefd);

    char cgiPath[PATH_MAX];
    char cgiName[PATH_MAX];

    novaNcgiSetupChildExecution(entry, conn, cgiPath, cgiName, uid);

    char FD[20];
    snprintf(FD, 20, "NCGI_FD=%d", localfd);
    char *env[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            FD,
            NULL
    };
    // int cwdfd = open("/proc/nova_cwd", O_RDWR);
    // if(!cwdfd) {
    //     perror("open nova_cwd");
    //     novaNcgiSendError(conn, 500);
    //     exit(1);
    // }
    // if(cwdfd != 3) {
    //     cwdfd = dup2(cwdfd, 3);
    //     if(cwdfd < 0) {
    //         perror("dup2 cwdfd");
    //         novaNcgiSendError(conn, 500);
    //         exit(1);
    //     }
    // }
    // char cwd[50];
    // if (getcwd(cwd, sizeof(cwd)) != NULL) {
    //     printf("Current working dir: %s\n", cwd);
    //     int ret = write(cwdfd, cwd, strlen(cwd)+1);
    //     if(ret < 0) {
    //         perror("write cwd");
    //         novaNcgiSendError(conn, 500);   
    //         exit(1);
    //     }
    // } else {
    //     perror("getcwd() error");
    //     novaNcgiSendError(conn, 500);   
    //     exit(1);
    // }

    if(execle(cgiPath, cgiName, NULL, env) < 0) {
        perror("execle");
        novaNcgiSendError(conn, 500);
        exit(1);
    }

    exit(0);
}

struct nova_map *novaNCGIMap = NULL;
struct nova_control_socket *novaHandleWithNCGIM(struct nova_handler_enrty *entry, nova_httpd_request *conn) {
    if(!novaNCGIMap) {
        novaNCGIMap = novaInitMap((int (*)(const void *, const void *))novaChannelComp); //argument is a function pointer
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

    // SETUP is complete. send the fd and close it
    int sent = novaSendFd(worker->sockfd, conn->sockfd, conn->buf, conn->buflen);

    if(sent <= 0) { //socket closed, possibly the process
        //TODO cleanup if any
        kill(worker->childpid, SIGTERM); //just a precaution
        close(worker->sockfd);
        ret = NULL;
        deletion(worker);
        channel->numWorking --;
        printf("previously assigned worker:%d seems dead\n", worker->childpid);

        return novaHandleWithNCGIM(entry, conn);
    }
    printf("Worker assinged: %d\n", worker->childpid);
    return ret;
}

void novaHandleNCGIControlSocket(struct nova_control_socket *ptr) {
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
}

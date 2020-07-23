/*
 * nova_httpd_util.c
 *
 *  Created on: Jul 16, 2020
 *      Author: abhijit
 */

#define _GNU_SOURCE //required for memmem
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/epoll.h>


#define __NOVA_SERVER_MAIN__
#include "nova_httpd.h"
#include "nova_http_request_handler.h"

#define MAX(x, y) (x > y ? x : y)


#define respond(x) novaHandle(x)

#define MAX_CONNECTIONS 512

struct nova_control_socket *handleRequest(nova_httpd_request *conn) {
    //need to make it blocking for further processing
    int flag = fcntl(conn->sockfd, F_GETFL);
    if (flag >=0 && fcntl(conn->sockfd, F_SETFL, flag & ~O_NONBLOCK) == -1) {
        perror("NONBLOCKING");
        exit(1);
    }
    int parsed = phr_parse_request_line((const char*) conn->buf, conn->buflen,
            (const char**) &conn->method, &conn->methodLen,
            (const char**) &conn->path, &conn->pathLen, &conn->version, 0);
    if(parsed != conn->buflen){
        printf("Assert failed: %d != %ld", parsed, conn->buflen);
    }
    assert(parsed == conn->buflen);
    return respond(conn);
}

//start server
static int listenServer(const char *port, int blocking) {
    struct addrinfo hints, *res, *p;
    int listenfd;

    // getaddrinfo for host
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo( NULL, port, &hints, &res) != 0) {
        perror("getaddrinfo() error");
        exit(1);
    }

    for (p = res; p != NULL; p = p->ai_next) {
        int option = 1;
        listenfd = socket(p->ai_family, p->ai_socktype, 0);
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
        if (listenfd == -1)
            continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
            break;
    }

    if (p == NULL) {
        perror("socket() or bind()");
        exit(1);
    }

//    int flag = FD_CLOEXEC;
    if (fcntl(listenfd, F_SETFD, FD_CLOEXEC) == -1) { //making child process wont have access to it
        perror("fcntl set FD_CLOEXEC");
        exit(1);
    }
    if(!blocking) {
        int flag = fcntl(listenfd, F_GETFL);
        if (flag >=0 && fcntl(listenfd, F_SETFL, flag | O_NONBLOCK) == -1) {
            perror("NONBLOCKING");
            exit(1);
        }
    }

    int option = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option))
            < 0) {
        perror("setsockopt()");
    }

    freeaddrinfo(res);

    // listen for incoming connections
    if (listen(listenfd, 1000000) != 0) {
        perror("listen() error");
        exit(1);
    }
    return listenfd;
}

#if 1
void novaHttpdServer(char *port) {
#define MAX_EVENTS 100
#define REMOVE_CLOSE_FD(fd) {\
                                if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) { \
                                    perror("epoll_ctl: " # fd " at " NOVA_FILE_N_LINE); \
                                    fprintf(stderr, #fd " = %d, errno= %d\n", fd, errno); \
                                    exit(EXIT_FAILURE); \
                                } \
                                close(fd); \
                            }

    nova_httpd_request _connections[MAX_CONNECTIONS],
            *connPool[MAX_CONNECTIONS];
    int conPoolLen = 0;
    struct epoll_event ev, events[MAX_EVENTS];
    int listen_sock, conn_sock, nfds, epollfd;

    struct sockaddr_in addr;
    socklen_t addrlen;

    for (; conPoolLen < MAX_CONNECTIONS; conPoolLen++) {
        connPool[conPoolLen] = &_connections[conPoolLen];
    }


    listen_sock = listenServer(port, 0);

    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1) {
        perror("epoll_ctl: listen_sock");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }
        int n;
        for (n = 0; n < nfds; ++n) {
            if (events[n].data.fd == listen_sock) {
                conn_sock = accept4(listen_sock, (struct sockaddr*) &addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (conn_sock == -1) {
                    perror("accept");
                    exit(EXIT_FAILURE);
                }
                if (conPoolLen <= 0) {
                    close(conn_sock);
                    continue;
                }

                conPoolLen -= 1;
                nova_httpd_request *ptr = connPool[conPoolLen];
                *ptr = (nova_httpd_request ) {
                            .socktype = NOVA_SOCK_TYPE_REQ,
                            .sockfd = conn_sock,
                            .buflen = 0
                        };

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = conn_sock;
                ev.data.ptr = ptr;
//                conPoolLen -= 1;
//                ev.data.ptr = connPool[conPoolLen];

                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1) {
                    perror("epoll_ctl: conn_sock");
                    exit(EXIT_FAILURE);
                }
            } else {

                nova_httpd_request *conn = events[n].data.ptr;
                if (conn->socktype == NOVA_SOCK_TYPE_REQ) {
                    int findEoH = novaPeekTillFirstLine(conn);
                    if (findEoH == -2) {
                        REMOVE_CLOSE_FD(conn->sockfd);
                        conn->sockfd = 0;
                        continue;
                    }
                    if (findEoH < 0) {
                        REMOVE_CLOSE_FD(conn->sockfd);
                        conn->sockfd = 0;
                        continue;
                    }
                    if(findEoH == 0) {
                        printf("Continuing for more data: %ld\n", conn->buflen);
                        continue;
                    }

                    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->sockfd, NULL) == -1) {
                        perror("epoll_ctl: conn_sock");
                        exit(EXIT_FAILURE);
                    }

                    struct nova_control_socket *ret =  handleRequest(conn);
                    if(ret != NULL) {
                        int flag = fcntl(ret->sockfd, F_GETFL);
                        if (flag >=0 && fcntl(conn->sockfd, F_SETFL, flag | O_NONBLOCK) == -1) {
                            perror("NONBLOCKING");
                            exit(1);
                        }
                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.fd = ret->sockfd;
                        ev.data.ptr = ret;
                        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ret->sockfd, &ev) == -1) {
                            perror("epoll_ctl: conn_sock");
                            exit(EXIT_FAILURE);
                        }
                    }
                    fprintf(stderr, "closing fd for path: %s\n", conn->path);
//                    REMOVE_CLOSE_FD(conn->sockfd);
                    close(conn->sockfd);
                    conn->sockfd = 0;
                    connPool[conPoolLen] = conn;
                    conPoolLen += 1;

                } else if(conn->socktype == NOVA_SOCK_TYPE_CTL) {
                    struct nova_control_socket *ptr = (struct nova_control_socket *)conn;
                    handleControlConnection(ptr);
                }
            }
        }

        CLEAN_UP_ZOMBIES;
    }
}
#else

void novaHttpdServer(char *port) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int clientFd;
    int maxfd = 0;
    nova_httpd_request connections[MAX_CONNECTIONS]; //TODO optimize
    int listenfd;

	fd_set rfds;

    listenfd = listenServer(port, 0);

    maxfd = listenfd;
	while(1){
		FD_ZERO(&rfds);
		maxfd = listenfd;
        FD_SET(listenfd, &rfds);
        int x;
		for(x = 0; x < MAX_CONNECTIONS; x++) { //TODO optimize by defering
            if(!connections[x].sockfd) continue;
			FD_SET(connections[x].sockfd, &rfds);
			if(maxfd < connections[x].sockfd)
				maxfd = connections[x].sockfd;
		}

		int selRet = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if(selRet < 0) {
            if(errno == EINTR) //incase of interupt ignore TODO handle it later
                continue;
            perror("select");
            return;
        }

        if(FD_ISSET(listenfd, &rfds)) { //accept will be called at the end
            addrlen = sizeof(clientaddr);
            clientFd = accept4 (listenfd, (struct sockaddr *) &clientaddr, &addrlen, SOCK_CLOEXEC);
            if(clientFd <= 0)
                continue;

            if(clientFd == MAX_CONNECTIONS) {
                cleanClose(clientFd);
                continue;
            }

            connections[clientFd] = (nova_httpd_request) {
                                       .sockfd = clientFd,
                                       .buflen = 0
                                };
        }

        for(x = 0; x < MAX_CONNECTIONS; x ++) {
            nova_httpd_request *conn = &connections[x];
            if(FD_ISSET(conn->sockfd, &rfds)) {
                int findEoH = novaPeekTillFirstLine(conn);
                if(findEoH == -2) {
                    close(conn->sockfd);
                    conn->sockfd = 0;
                    continue;
                }
                if(findEoH < 0) { //TODO -2 means overflow
                    forceClose(conn->sockfd);
                    conn->sockfd = 0;
                    continue;
                }

                handleRequest(conn);
                close(conn->sockfd);
                conn->sockfd = 0;
            }
        }
        CLEAN_UP_ZOMBIES;
    }
}
#endif

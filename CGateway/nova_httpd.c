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

#include "nova_httpd.h"
#include "nova_http_request_handler.h"

#define MAX(x, y) (x > y ? x : y)

// static void respondUsingFork(nova_request_connect *conn);
// static void respondFromFork(nova_request_connect *conn);

#define respond(x) novaHandle(x)

#define MAX_CONNECTIONS 512

static void cleanClose(int sock) {
    char buf[EIGHT_KB]; //header should not be bigger than this.
    recv(sock, buf, EIGHT_KB, MSG_DONTWAIT);
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

static void forceClose(int sock) {
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

#define readTillEoH(x) readTillDelim(x, "\r\n\r\n", 4)
#define readTillFirstLine(x) readTillDelim(x, "\r\n", 2)

#define CLEAN_UP_ZOMBIES while(1) { \
            int status; \
            pid_t childpid = waitpid(0, &status, WNOHANG); \
            if(childpid < 0) break; \
        }

static int readTillDelim(nova_request_connect *conn, const char *delim, int delimLen) {
    char *bufptr = conn->buf + conn->buflen;
    int rlen = recv(conn->sockfd, bufptr, EIGHT_KB - conn->buflen, MSG_PEEK);
    // the idea here is to read upto end of the header and end of header only. Not single byte from the
    if(rlen <= 0) { //TODO
        return -1;
    }
    char *searchptr = conn->buf + MAX(0, conn->buflen + 1 - delimLen); //just in case part of crlf was in last read
    char *crlf = memmem(searchptr, (rlen + bufptr - searchptr), delim, delimLen);
    if(crlf) {
        rlen = delimLen + crlf - bufptr;
    }
    int newRlen = recv(conn->sockfd, bufptr, rlen, 0); //clear up the buffer
    assert(newRlen == newRlen); //TODO add other handler
    conn->buflen += rlen;

    if(!crlf && conn->buflen == EIGHT_KB) {
        return -2;
    }

    return !!crlf; //return 0 or 1
}

int readNParseHeaders(nova_request_connect *conn) {
    size_t prevlen = conn->buflen;
    while(1) {
        int findEoH = readTillEoH(conn);
        if(findEoH == -2) {
            close(conn->sockfd);
            conn->sockfd = 0;
            exit(2);
        }
        if(findEoH < 0) { //TODO -2 means overflow
            forceClose(conn->sockfd);
            conn->sockfd = 0;
            continue;
        }
        break;
    }
    conn->headerLen = MAX_HEADERS;
    int parsed = phr_parse_headers((const char *)conn->buf + prevlen, conn->buflen - prevlen,
                            conn->headers, &conn->headerLen, 0);
    if(parsed < 0) {
        return -1;
    }

    int i;
    for(i = 0; i < conn->headerLen; i++) {
        int j = conn->headers[i].name - conn->buf;
        conn->buf[j + conn->headers[i].name_len] = 0;
        j = conn->headers[i].value - conn->buf;
        conn->buf[j + conn->headers[i].value_len] = 0;
    }
    return 0;
}

void cleanUpRecvBuf(int sockfd) {
    char *buf[EIGHT_KB];
    recv(sockfd, buf, EIGHT_KB, MSG_DONTWAIT);
}


#if 0
static void respondFromFork(nova_request_connect *conn) {
    size_t prevlen = conn->buflen;
    while(1) {
        int findEoH = readTillEoH(conn);
        if(findEoH == -2) {
            close(conn->sockfd);
            conn->sockfd = 0;
            exit(2);
        }
        if(findEoH < 0) { //TODO -2 means overflow
            forceClose(conn->sockfd);
            conn->sockfd = 0;
            continue;
        }
        break;
    }
    conn->headerLen = MAX_HEADERS;
    int parsed = phr_parse_headers((const char *)conn->buf + prevlen, conn->buflen - prevlen,
                            conn->headers, &conn->headerLen, 0);
    if(parsed <= 0) {
        fprintf(stderr, "Error in parser: %d\n", parsed);
        printf("%.*s\n", (int)conn->buflen, conn->buf);
        return;
    }
    dup2(conn->sockfd, STDOUT_FILENO);
    close(conn->sockfd);

    printf("HTTP/1.1 200 OK\r\n\r\n");
    printf("Hello! There");
    printf("The request is: %d\n", parsed);
    printf("%.*s %.*s HTTP/%d\n", (int)conn->methodLen, conn->method, (int)conn->pathLen, conn->path, conn->version);
    printf("QueryString: %.*s\n", (int)conn->queryStringLen, conn->queryString);
    int i;
    for(i = 0; i < conn->headerLen; i++) {
        printf("%.*s: %.*s\n", (int)conn->headers[i].name_len, conn->headers[i].name, (int)conn->headers[i].value_len, conn->headers[i].value);
    }

    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
}

static void respondUsingFork(nova_request_connect *conn) {
    pid_t pid;
    pid = fork();
    if(pid < 0) {
        perror("fork");
        exit(0);
    }

    if(pid) { // parent
        return;
    }
    respondFromFork(conn);
    exit(0);
}
#endif

static int percent_decode(char *buffer, size_t size) {
    static const char tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
         0, 1, 2, 3, 4, 5, 6, 7,  8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1
    };

    char *in = buffer;
    char *out = buffer;
    char c, v1, v2;
    while(in - buffer < size) {
        c = *in;
        if(c=='%' &&
                (v1 = tbl[(unsigned char) in[1]]) >= 0 &&
                (v2 = tbl[(unsigned char) in[2]]) >= 0) {
            c = (v1<<4) | v2;
            in += 2;
        }
        *out = c;
        out ++;
        in ++;
    }

    return out - buffer;
}

void requestHandler(nova_request_connect *conn) {
    int parsed = phr_parse_request_line((const char *)conn->buf, conn->buflen,
            (const char **)&conn->method, &conn->methodLen,
            (const char **)&conn->path, &conn->pathLen,
            &conn->version, 0);
    assert(parsed == conn->buflen);
    conn->queryString = memchr(conn->path, '?', conn->pathLen);
    if(conn->queryString) {
        conn->queryString ++;
        conn->queryStringLen = conn->path + conn->pathLen - conn->queryString;
        conn->pathLen = conn->queryString - conn->path;
    }
    //TODO perform a url decoding for the path
    conn->pathLen = percent_decode(conn->path, conn->pathLen);
    respond(conn);
}

//start server
static int startServer(const char *port)
{
    struct addrinfo hints, *res, *p;
    int listenfd;

    // getaddrinfo for host
    memset (&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo( NULL, port, &hints, &res) != 0)
    {
        perror ("getaddrinfo() error");
        exit(1);
    }
    // socket and bind
    for (p = res; p!=NULL; p=p->ai_next)
    {
        int option = 1;
        listenfd = socket (p->ai_family, p->ai_socktype, 0);
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
        if (listenfd == -1) continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
    }

    if (p==NULL)
    {
        perror ("socket() or bind()");
        exit(1);
    }

    if (fcntl(listenfd, F_SETFD, FD_CLOEXEC) == -1) { //making child process wont have access to it
        perror("fcntl set FD_CLOEXEC");
        exit(1);
    }

    int option = 1;
    if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0){
        perror("setsockopt()");
    }

    freeaddrinfo(res);

    // listen for incoming connections
    if ( listen (listenfd, 1000000) != 0 )
    {
        perror("listen() error");
        exit(1);
    }
    return listenfd;
}

void novaHttpdServer(char *port) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int clientFd;
    int maxfd = 0;
    nova_request_connect connections[MAX_CONNECTIONS]; //TODO optimize
    int listenfd;

	fd_set rfds;

    listenfd = startServer(port);

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
            clientFd = accept (listenfd, (struct sockaddr *) &clientaddr, &addrlen);
            if(clientFd <= 0)
                continue;

            if(clientFd == MAX_CONNECTIONS) {
                cleanClose(clientFd);
                continue;
            }

            connections[clientFd] = (nova_request_connect) {
                                       .sockfd = clientFd,
                                       .buflen = 0
                                };
        }

        for(x = 0; x < MAX_CONNECTIONS; x ++) {
            nova_request_connect *conn = &connections[x];
            if(FD_ISSET(conn->sockfd, &rfds)) {
                int findEoH = readTillFirstLine(conn);
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

                requestHandler(conn);
                close(conn->sockfd);
                conn->sockfd = 0;
            }
        }
        CLEAN_UP_ZOMBIES;
    }
}

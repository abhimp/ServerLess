#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/uio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <assert.h>


#include "../nova_httpd_util.h"
#include "../nova_http_status_code.h"
#include "../picohttpparser.h"


struct ncgiInfo {
    int sockfd;
};

extern char **environ;

static int ncgiStart(){
    int ncgiFD = 4;
    char *ncgi_fd = getenv("NCGI_FD");
    if(ncgi_fd) {
        ncgiFD = atoi(ncgi_fd);
    }

    return ncgiFD;
}

static int ncgiAccept(int ncgiFd, struct sockaddr *restrict address,
        socklen_t *restrict address_len) {
    int recvFd = 0;
    char retBuf[EIGHT_KB];
    int ret = novaRecvFd(ncgiFd, &recvFd, retBuf, sizeof(retBuf));
    if (ret <= 0) {
        return -1;
    }
    if(getpeername(recvFd, address, address_len) < 0) {
        close(recvFd);
        //TODO report back
        return -1;
    }
    return recvFd;
}


void *ncgiInitServer() {
    struct ncgiInfo *pack = malloc(sizeof(struct ncgiInfo));
    pack->sockfd = ncgiStart();

    return pack;
}



static char * (*storeEnv())[2] {
    int envCnt = 0;
    int totalLen = 0;
    for(; environ[envCnt]; envCnt++) totalLen += strlen(environ[envCnt]) + 1;

    char *envStorage = malloc(totalLen*sizeof(char));
    char *(*env)[2] = malloc((envCnt + 1)*sizeof(char *[2]));
    int curPos = 0;
    for(int i = 0; i < envCnt; i++) {
        env[i][0] = envStorage + curPos;
        strcpy(envStorage + curPos, environ[i]);
        char *pos = strchr(envStorage + curPos, '=');
        *pos = 0;
        env[i][1] = pos + 1;
        curPos += strlen(environ[i]) + 1;
    }
    env[envCnt][0] = NULL;
    return env;
}

void sendError(nova_httpd_request *conn, int status) {
#define HTTP_10 "HTTP/1.0 "
#define CRLF "\r\n"
#define PLAIN_TEXT "Content-type: text/plain" CRLF
    cleanUpRecvBuf(conn->sockfd);
    struct iovec iov[] = {
            {HTTP_10, strlen(HTTP_10)},
            {(char *)HTTP_RESPONSE_STATUS[status], strlen(HTTP_RESPONSE_STATUS[status])},
            {CRLF, strlen(CRLF)},
            {PLAIN_TEXT, strlen(PLAIN_TEXT)},
            {CRLF, strlen(CRLF)},
    };
    int iovcnt = sizeof(iov) / sizeof(struct iovec);

    writev(conn->sockfd, iov, iovcnt);
    close(conn->sockfd);
#undef HTTP_10
#undef CRLF
#undef PLAIN_TEXT
}



static int setEnv(int childFd, struct sockaddr const *address, socklen_t address_len, char *(*env)[2]) {
#define SEND_500_ERROR(x) { \
        perror(x); \
        sendError(conn, 500); \
    }
#define ADD2ENV(x, y) { \
    if(setenv(x, y, 1) < 0) { \
        SEND_500_ERROR("setenv"); \
        assert(0); \
        return -1; \
    }\
}
    nova_httpd_request connStorage = { .sockfd = childFd };
    nova_httpd_request *conn;
    conn = &connStorage;

    novaReadNParseHeaders(conn);

    for(int i = 0; i < conn->headerLen; i++) {
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
    for(int i = 0; env[i][0]; i++) {
        ADD2ENV(env[i][0], env[i][1]);
//        putenv((char *)env[i]);
    }
#undef ADD2ENV
#undef SEND_500_ERROR

    return 0;
}

void ncgiRunForever(void *ptr, void (*handler)(void)) {
    char *(*env)[2] = storeEnv();
    struct sockaddr_storage address;
    socklen_t address_len;
    int childFd;
    fflush(stdout);
    int stdinfd = dup(STDIN_FILENO);
    int stdoutfd = dup(STDOUT_FILENO);

    struct ncgiInfo *info = ptr;

    while(1){
        address_len = sizeof(address);
        childFd = ncgiAccept(info->sockfd, (struct sockaddr *)&address, &address_len);
        if(childFd < 0){
            exit(1);
        }
        if(setEnv(childFd, (struct sockaddr *)&address, address_len, env) < 0)
            exit(8);

        if(dup2(childFd, STDIN_FILENO) < 0)
            perror("dup2");
        if(dup2(childFd, STDOUT_FILENO) < 0)
            perror("dup2");
//        close(childFd);

        handler();

        fflush(stdout);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(childFd);
        send(info->sockfd, "Hello", 5, 0);
    }
}

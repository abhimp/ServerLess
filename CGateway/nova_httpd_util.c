/*
 * nova_httpd_util.c
 *
 *  Created on: Jul 16, 2020
 *      Author: abhijit
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <sys/socket.h>
#include <assert.h>

#include "nova_http_status_code.h"
#include "nova_httpd_util.h"

static char const PERCENT_DECODE_TABLE[256] = {
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

int novaHttpdPercentDecode(char *buffer, size_t size) {

    char const *tbl = PERCENT_DECODE_TABLE;

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


#define MAX(x,y) (x>y?x:y)
int novaReadTillDelim(nova_request_connect *conn, const char *delim,
        int delimLen, int peek) {
    char *bufptr = conn->buf + conn->buflen;
    int rlen = recv(conn->sockfd, bufptr, EIGHT_KB - conn->buflen, MSG_PEEK);
    // the idea here is to read upto end of the header and end of header only. Not single byte from the
    if (rlen <= 0) { //TODO
        return -1;
    }
    char *searchptr = conn->buf + MAX(0, conn->buflen + 1 - delimLen); //just in case part of crlf was in last read
    char *crlf = memmem(searchptr, (rlen + bufptr - searchptr), delim,
            delimLen);
    if (crlf) {
        rlen = delimLen + crlf - bufptr;
    }
    else{
        return 0;
    }
    if(!peek) {
        int newRlen = recv(conn->sockfd, bufptr, rlen, 0); //clear up the buffer
        assert(newRlen == newRlen); //TODO add other handler
    }
    conn->buflen += rlen;

    if (!crlf && conn->buflen == EIGHT_KB) {
        return -2;
    }

    return !!crlf; //return 0 or 1
}

/*
 * This function assumes that no data is read til now. Whatever we have is peeked.
 */
int novaReadNParseHeaders(nova_request_connect *conn) { //it assumes that the
    conn->buflen = 0;
    while (1) {
        int findEoH = novaReadTillEoH(conn);
        if (findEoH == -2) {
            close(conn->sockfd);
            conn->sockfd = 0;
            exit(2);
        }
        if (findEoH < 0) { //TODO -2 means overflow
            close(conn->sockfd);
            conn->sockfd = 0;
            continue;
        }
        break;
    }
    conn->headerLen = MAX_HEADERS;
    int parsed = phr_parse_request((const char*) conn->buf, conn->buflen,
            (const char **)&conn->method, &conn->methodLen, (const char **)&conn->path, &conn->pathLen, &conn->version,
            conn->headers, &conn->headerLen, 0);
    if (parsed < 0) {
        return -1;
    }

//    int i;
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

    for (int i = 0; i < conn->headerLen; i++) {
        int j = conn->headers[i].name - conn->buf;
        conn->buf[j + conn->headers[i].name_len] = 0;
        j = conn->headers[i].value - conn->buf;
        conn->buf[j + conn->headers[i].value_len] = 0;
    }
    return 0;
}


#define DEREFENCE_STRUCT(st, mem, ptr) \
    ((st *)(((char *) ptr) - (char *)(&((st *)NULL)->mem)))
/*******************************************************
 * Requests
 *******************************************************/

const char *novaGetHttpRequestHeader(const void *headers, const char *name) {
    nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
    int i;
    for(i = 0; i < conn->headerLen; i++) {
        if(strncasecmp(name, conn->headers[i].name, conn->headers[i].name_len) == 0) {
            return conn->headers[i].value;
        }
    }
    return NULL;
}

int novaGetHttpRequestHeaderCnt(const void *headers) {
    nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
    return (int)conn->headerLen;
}

int novaGetHttpRequestHeaderValue(const void *headers, int id, const char **name, const char **val) {
    nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
    *name = NULL;
    *val = NULL;
    if(id >= conn->headerLen) {
        return 0;
    }
    *name = conn->headers[id].name;
    *val = conn->headers[id].value;
    return 1;
}

const char *novaGetQueryString(const void *headers) {
    nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
    return conn->queryString;
}

/*******************************************************
 * Response
 *******************************************************/
void novaStartResponseHeader(void *headers, int statuscode) {
    nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
    conn->response.statuscode = statuscode;
}
void novaAddResponseHeader(void *headers, const char *name, const char *value) {
    nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
    int i;
    for(i = 0; i < MAX_HEADERS-1; i++) {
        if(conn->response.headers[i][0] == NULL) {
            conn->response.headers[i][0] = name;
            conn->response.headers[i][1] = value;
            break;
        }
    }
}
void novaEndResponseHeaderFile(void *headers, FILE *fp) {
    nova_request_connect *conn = DEREFENCE_STRUCT(nova_request_connect, headers, headers);
    FILE *tmpfp = fp;
    if(fp == NULL) {
        int ffd = dup(conn->sockfd);
        tmpfp = fdopen(ffd, "w");
    }
    fprintf(tmpfp, "HTTP/1.0 %s\r\n", HTTP_RESPONSE_STATUS[conn->response.statuscode]);
    int i;
    int contentType = 0;
    for(i = 0; i < MAX_HEADERS && conn->response.headers[i][0]; i++) {
        fprintf(tmpfp, "%s: %s\r\n", conn->response.headers[i][0], conn->response.headers[i][1]);
        if(strcasecmp("Content-Type", conn->response.headers[i][0]) == 0)
            contentType = 1;
    }
    if(!contentType)
        fprintf(tmpfp, "Content-Type: text/plain\r\n");
    fprintf(tmpfp, "\r\n");
    fflush(tmpfp);
    if(fp == NULL)
        fclose(tmpfp);
}

/*******************************************************
 * END REQUEST-RESPONSE
 *******************************************************/

struct nova_map *novaInitMap(int (*comp)(const void *, const void *)) {
    struct nova_map *map;
    map = malloc(sizeof(struct nova_map));
    *map = (struct nova_map) {
        .array = NULL,
        .count = 0,
        .capa = 0,
        .comp = comp
    };
    return map;
}

void novaDestroyMap(struct nova_map **map, void (*deallocate)(const void *)) {
    int i;
    for(i = 0; i < (*map)->count; i++) {
        deallocate((*map)->array[i]);
    }
    free(*map);
    *map = NULL;
}

int novaAddToMap(struct nova_map *map, const void *ele) {
    for(int i = 0; i < map->count; i++) {
        if(map->comp(map->array[i], ele) == 0) {
            return -1;
        }
    }
    if(map->capa == map->count) {
        map->capa += 32; //don't know wny 32
        map->array = realloc(map->array, sizeof(void *)*map->capa);
    }
    map->array[map->count] = ele;
    map->count += 1;
    return 1;
}
const void *novaSearch(struct nova_map *map, const void *key) {
    for(int i = 0; i < map->count; i++) {
        if(map->comp(map->array[i], key) == 0) {
            return map->array[i];
        }
    }
    return NULL;
}
int novaDelFromMap(struct nova_map *map, const void *ele){
    int found = -1;
    for(int i = 0; i < map->count; i++) {
        if(map->comp(map->array[i], ele) == 0) {
            found = i;
            break;
        }
    }
    if(found > -1) {
        map->count -= 1;
        map->array[found] = map->array[map->count];
        return 1;
    }
    return -1;
}


int novaSendFd(int unix_sock, int fd, void *sendBuf, size_t sendBufLen) {
    if (!sendBuf || !sendBufLen) return -1;
    struct iovec iov = {.iov_base = sendBuf, // Must send at least one byte
                        .iov_len = sendBufLen};

    union {
        char buf[CMSG_SPACE(sizeof(fd))];
        struct cmsghdr align;
    } u;

    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = u.buf,
                         .msg_controllen = sizeof(u.buf)};

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    *cmsg = (struct cmsghdr){.cmsg_level = SOL_SOCKET,
                             .cmsg_type = SCM_RIGHTS,
                             .cmsg_len = CMSG_LEN(sizeof(fd))};

    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    return sendmsg(unix_sock, &msg, 0);
}


int novaRecvFd(int unix_sock, int *recvfd, void *retBuf, size_t retBufCapa) {
#define MAXLINE EIGHT_KB //don't want loose a data due what ever the reason
#define CONTROL_LEN 1024
#define MIN(x, y) (x < y ? x : y)

    int             nr;
    char            buf[MAXLINE];
    char            contrl_buf[CONTROL_LEN];

    retBufCapa = retBuf ? retBufCapa : 0;
    if(!recvfd) return -1;

    struct iovec iov = {
                .iov_base = buf,
                .iov_len = MAXLINE
            };

    struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = contrl_buf,
                .msg_controllen = CONTROL_LEN
            };

    if ((nr = recvmsg(unix_sock, &msg, 0)) < 0) {
        perror("recvmsg");
        return -1;
    } else if (nr == 0) {
        fprintf(stderr, "connection closed by server\n");
        return 0;
    }

    if(retBuf || retBufCapa)
        memcpy(retBuf, iov.iov_base, MIN(iov.iov_len, retBufCapa));

    *recvfd = -1;
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&recvfd, CMSG_DATA(cmsg), sizeof(int));
            break;
        }
    }

    return MIN(iov.iov_len, retBufCapa);
#undef MAXLINE
#undef CONTROL_LEN
#undef MIN
}

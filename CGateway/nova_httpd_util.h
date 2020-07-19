/*
 * nova_httpd_util.h
 *
 *  Created on: Jul 16, 2020
 *      Author: abhijit
 */

#ifndef NOVA_HTTPD_UTIL_H_
#define NOVA_HTTPD_UTIL_H_
#include <stdio.h>
#include "picohttpparser.h"

#define EIGHT_KB 8192
#define MAX_HEADERS 50

enum _epoll_type {
	NOVA_SOCK_TYPE_REQ,
	NOVA_SOCK_TYPE_CTL
};

//struct _http_response_ {
//    int statuscode;
//    const char *headers[MAX_HEADERS][2];
//};

struct _http_request_header_ {
	enum _epoll_type socktype;
    int sockfd;
    char *method, *path;
    size_t methodLen, pathLen;
    int version;
    char *queryString;
    size_t queryStringLen;
    struct phr_header headers[MAX_HEADERS];
    size_t headerLen;
    char buf[EIGHT_KB]; //maximum header length allowed in apache
    size_t buflen;
//    struct _http_response_ response; //  although it is increasing the overall size of the struct,
                                    // it is allowing me doing everything without memory management.
};

typedef struct _http_request_header_ nova_httpd_request;

struct nova_map {
    void const **array;
    int count;
    int capa;
    int (*comp)(const void *, const void *);
};

struct nova_map *novaInitMap(int (*comp)(const void *, const void *));
void novaDestroyMap(struct nova_map **map, void (*deallocate)(const void *));
int novaAddToMap(struct nova_map *map, const void *ele); //Map wont copy anything, rather keep the value as if it is a pointer
const void *novaSearch(struct nova_map *map, const void *key);
int novaDelFromMap(struct nova_map *map, const void *ele);

int novaReadTillDelim(nova_httpd_request *conn, const char *delim, int delimLen, int peek);
#define novaReadTillEoH(x) novaReadTillDelim(x, "\r\n\r\n", 4, 0)
#define novaPeekTillFirstLine(x) novaReadTillDelim(x, "\r\n", 2, 1)

int novaHttpdPercentDecode(char *buffer, size_t size);
int novaReadNParseHeaders(nova_httpd_request *conn);



const char *novaGetHttpRequestHeader(const void *headers, const char *name);
int novaGetHttpRequestHeaderCnt(const void *headers);
int novaGetHttpRequestHeaderValue(const void *headers, int id, const char **name, const char **val);
const char *novaGetQueryString(const void *headers);


//void novaStartResponseHeader(void *headers, int statuscode);
//void novaAddResponseHeader(void *headers, const char *name, const char *value);
//void novaEndResponseHeaderFile(void *headers, FILE *fp);
//#define novaEndResponseHeaderStd(x) novaEndResponseHeaderFile(x, stdout)
//#define novaEndResponseHeader(x) novaEndResponseHeaderFile(x, NULL)

int novaSendFd(int unix_sock, int fd, void *sendBuf, size_t sendBufLen);
int novaRecvFd(int unix_sock, int *recvfd, void *retBuf, size_t retBufCapa);

void cleanUpRecvBuf(int sockfd);
#endif /* NOVA_HTTPD_UTIL_H_ */

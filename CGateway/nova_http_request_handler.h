#ifndef __NOVA_HTTP_REQUEST_HANDLER_H__
#define __NOVA_HTTP_REQUEST_HANDLER_H__
int readNParseHeaders(nova_request_connect *conn);
void cleanUpRecvBuf(int sockfd);
#endif

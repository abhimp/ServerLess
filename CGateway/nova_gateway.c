#include <stdio.h>
#include "nova_httpd.h"
#include "nova_userland.h"


void basicHandler(const char *path, const char *method, const void *headers) {
    printf("\r\n");
    printf("Hi there\n");
    printf("there r %d headers\n", novaGetHttpRequestHeaderCnt(headers));
    int i;
    const char *name;
    const char *value;
    for(i = 0; i < novaGetHttpRequestHeaderCnt(headers); i++) {
        novaGetHttpRequestHeaderValue(headers, i, &name, &value);
        printf("%s: %s\n", name, value);
    }
}

// int novaRegisterHandler(char *route, char *method, enum nova_route_type type, char *cdir, nova_route_handler handler);
int main(int argc, char *argv[]) {
    printf("This is nova\n");
    novaRegisterHandler("/", NULL, NOVA_ROUTE_FUNC, NULL, basicHandler);
    novaHttpdServer("9087");
    return 0;
}

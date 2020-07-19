#include <stdio.h>
#include "nova_httpd.h"
#include "nova_userland.h"


void basicHandler(const char *path, const char *method, const void *headers) {
    printf("\r\n");
    printf("Hi there\n");
    printf("The path: %s \n", path);
    printf("The query: %s \n", novaGetQueryString(headers));
    printf("there r %d headers\n", novaGetHttpRequestHeaderCnt(headers));
    int i;
    const char *name;
    const char *value;
    for(i = 0; i < novaGetHttpRequestHeaderCnt(headers); i++) {
        novaGetHttpRequestHeaderValue(headers, i, &name, &value);
        printf("%s: %s\n", name, value);
    }
}

// int novaRegisterHandler(char *route, char *method, char *cdir, nova_route_handler handler);
int main(int argc, char *argv[]) {
    printf("This is nova\n");
    novaRegisterHandler("/", NULL, NOVA_ROUTE_FUNC, NULL, basicHandler);
    novaRegisterHandler("/cgi/", NULL, NOVA_ROUTE_CGI, "/tmp/test/", NULL);
    novaRegisterHandler("/cgi-python/", NULL, NOVA_ROUTE_NCGI, "example_python/", NULL);
    novaHttpdServer("9087");
    return 0;
}

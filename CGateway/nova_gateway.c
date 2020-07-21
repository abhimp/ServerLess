#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "nova_httpd.h"
#include "nova_userland.h"

static int CLIENT_FUNCTION_GROUP_ID = 0;
static int CLIENT_FUNCTION_USER_ID = 0;



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


//typedef int (*nova_child_setup)(const char *path, const char *method, const char *exe, const void *headers);
int configNcgimExec(const char *path, const char *method, const char *exe, const void *headers) {
    if(setregid(CLIENT_FUNCTION_GROUP_ID, CLIENT_FUNCTION_GROUP_ID) < 0) {
        perror("setregid");
        return -1;
    }
    if(setreuid(CLIENT_FUNCTION_USER_ID, CLIENT_FUNCTION_USER_ID) < 0) {
        perror("setregid");
        return -1;
    }
    printf("gid: %d ", getgid());
    pid_t sessionId = setsid();
    if(sessionId < 0){
        perror("setsid");
        return -1;
    }

    printf("sessionid: %d\n", sessionId);

    return 0;
}

void setupUidGid(int argc, char *argv[]) {
    int opt;
    int uid = 0;
    int ugid = 0;
    int gid = 0;
    char *prog = argv[0];

    if(geteuid() != 0){
        fprintf(stderr, "%s need to run as root\n", prog);
        exit(1);
    }

    while ((opt = getopt(argc, argv, "u:g:")) != -1) {
        switch(opt) {
        case 'u':
            {
                uid = atoi(optarg);
                if(!uid) {
                    struct passwd *x = getpwnam(optarg);
                    assert(x);
                    uid = x->pw_uid;
                    ugid = x->pw_gid;
                }
                else{
                    struct passwd *x = getpwuid(uid);
                    if(x)
                        ugid = x->pw_gid;
                }
            }
            break;
        case 'g':
            {
                gid = atoi(optarg);
                if(!gid) {
                    struct group *x = getgrnam(optarg);
                    assert(x);
                    gid = x->gr_gid;
                }
            }
            break;
        default:
            exit(1);
        }
    }

    CLIENT_FUNCTION_GROUP_ID = gid ? gid : ugid;
    CLIENT_FUNCTION_USER_ID = uid;

    char *sg;
    char *ug;
    if((sg = getenv("SUDO_GID"))) {
        gid = atoi(sg);
        CLIENT_FUNCTION_GROUP_ID = CLIENT_FUNCTION_GROUP_ID ? CLIENT_FUNCTION_GROUP_ID : gid;
    }
    if((ug = getenv("SUDO_UID"))) {
        uid = atoi(ug);
        CLIENT_FUNCTION_USER_ID = CLIENT_FUNCTION_USER_ID ? CLIENT_FUNCTION_USER_ID : uid;
    }

    if(!CLIENT_FUNCTION_GROUP_ID || !CLIENT_FUNCTION_USER_ID){
        fprintf(stderr, "invalid group or user\n");
        exit(1);
    }

    printf("Function gid: %d, uid: %d\n", CLIENT_FUNCTION_GROUP_ID, CLIENT_FUNCTION_USER_ID);

    novaSetNid(CLIENT_FUNCTION_GROUP_ID);
    novaEnable();
}

// int novaRegisterHandler(char *route, char *method, char *cdir, nova_route_handler handler);
int main(int argc, char *argv[]) {
    setupUidGid(argc, argv);
    printf("This is nova\n");
    novaRegisterHandler("/", NULL, NOVA_ROUTE_FUNC, NULL, basicHandler, NULL);
    novaRegisterHandler("/cgi/", NULL, NOVA_ROUTE_NCGIS, "/tmp/test/", NULL, NULL);
    novaRegisterHandler("/cgi-python/", NULL, NOVA_ROUTE_NCGIM, "libpython/", NULL, NULL);
    novaRegisterHandler("/cgi-c/", NULL, NOVA_ROUTE_NCGIM, "libc/", NULL, configNcgimExec);
    novaHttpdServer("9087");
    return 0;
}

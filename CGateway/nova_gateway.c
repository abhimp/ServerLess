#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include "nova_httpd.h"
#include "nova_userland.h"

static int CLIENT_FUNCTION_GROUP_ID = 0;
static int CLIENT_FUNCTION_USER_ID = 0;
static char *SCRATCH_DIRECTORY = NULL;


static void basicHandler(const char *path, const char *method, const void *headers) {
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

static int prepareScrachDir(uid_t uid) {
    if(!SCRATCH_DIRECTORY)
        return 0;

    char scratchdir[PATH_MAX];
    snprintf(scratchdir, PATH_MAX, "%s/%d", SCRATCH_DIRECTORY, uid);

    if(mkdir(scratchdir, 0700) < 0) {
        perror("mkdir at " NOVA_FILE_N_LINE);
        return -1;
    }
    if(chown(scratchdir, uid, CLIENT_FUNCTION_GROUP_ID) < 0) {
        perror("chown at " NOVA_FILE_N_LINE);
        return -1;
    }
    if(chdir(scratchdir) < 0) {
        perror("chdir at " NOVA_FILE_N_LINE);
        return -1;
    }

    return 0;
}

//typedef int (*nova_child_setup)(const char *path, const char *method, const char *exe, const void *headers);
static int configNcgimExec(const char *path, const char *method, const char *exe, const void *headers, const int uid) {
    //Here the order should be setsid, setregid, setreuid. Once gid is set no other set operation will be permitted

    if(prepareScrachDir(uid) < 0)
        return -1;

    pid_t sessionId = setsid();
    if(sessionId < 0){
        perror("setsid");
        return -1;
    }

    printf("sessionid: %d\n", sessionId);

    if(setregid(CLIENT_FUNCTION_GROUP_ID, CLIENT_FUNCTION_GROUP_ID) < 0) {
        perror("setregid at " __FILE__);
        return -1;
    }

    if(setreuid(uid, uid) < 0) {
        perror("setreuid at " __FILE__);
        return -1;
    }
    printf("gid: %d \n", getgid());

    return 0;
}

static void setupUidGid(int argc, char *argv[]) {
    int opt;
    int uid = 0;
    int ugid = 0;
    int gid = 0;
    char *prog = argv[0];

    if(geteuid() != 0){
        fprintf(stderr, "%s need to run as root\n", prog);
        exit(1);
    }

    while ((opt = getopt(argc, argv, "u:g:d:")) != -1) {
        switch(opt) {
        case 'd':
            {
                SCRATCH_DIRECTORY = realpath(optarg, NULL);
                if(!SCRATCH_DIRECTORY) {
                    perror("realpath" " at " NOVA_FILE_N_LINE);
                    exit(1);
                }
            }
            break;
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

//    if(SCRATCH_DIRECTORY) {
//        if(mkdir(SCRATCH_DIRECTORY, 0777) < 0) {
//            perror("mkdir at " NOVA_FILE_N_LINE);
//            exit(1);
//        }
//        if(chown(SCRATCH_DIRECTORY, 0, CLIENT_FUNCTION_GROUP_ID) < 0) {
//            perror("chown at " NOVA_FILE_N_LINE);
//            exit(1);
//        }
//    }

    printf("Function gid: %d, uid: %d\n", CLIENT_FUNCTION_GROUP_ID, CLIENT_FUNCTION_USER_ID);

    novaSetNidMpid(CLIENT_FUNCTION_GROUP_ID, getpid());
    novaEnable();
}

// int novaRegisterHandler(char *route, char *method, char *cdir, nova_route_handler handler);
int main(int argc, char *argv[]) {
    setupUidGid(argc, argv);
    printf("This is nova\n");
    novaRegisterHandler("/", NULL, NOVA_ROUTE_FUNC, NULL, basicHandler, NULL);
    novaRegisterHandler("/cgi/", NULL, NOVA_ROUTE_NCGIS, "/tmp/test/", NULL, NULL);
    novaRegisterHandler("/cgi-python/", NULL, NOVA_ROUTE_NCGIM, "libpython/", NULL, configNcgimExec);
    novaRegisterHandler("/cgi-c/", NULL, NOVA_ROUTE_NCGIM, "libc/examples/", NULL, configNcgimExec);
    novaRegisterHandler("/cgi-go/", NULL, NOVA_ROUTE_NCGIM, "libgo/examples/", NULL, configNcgimExec);
    novaRegisterNcgimHandler("/cgi-map/", NULL, "libgo/examples/", (struct nova_handler_map []) {{"testmap", "env"}, {"hello", "hellonova"}, {NULL, NULL}}, configNcgimExec);
    
    novaRegisterNcgimHandler("/cgi-hotel-reservation/", NULL, "libgo/hotelReservation/services/frontend", 
        (struct nova_handler_map []) {
            {"frontend", "frontend"}, 
            {NULL, NULL}
        }, 
        configNcgimExec);
    novaRegisterNcgimHandler("/cgi-hotel-reservation-api/", NULL, "libgo/hotelReservation/services/", 
        (struct nova_handler_map []) {
            {"geo", "geo/geo"},
            {"user", "user/user"}, 
            {"rate", "rate/rate"}, 
            {"profile", "profile/profile"}, 
            {"reservation", "reservation/reservation"}, 
            {"search", "search/search"}, 
            {"recommendation", "recommendation/recommendation"}, 
            {NULL, NULL}
        }, 
        configNcgimExec);
    novaHttpdServer("9087");
    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "nova_uapi.h"

int main(int argc, char *argv[]) {
    char buf[sizeof(struct nova_user2lkm) + sizeof(int32_t)]; //enought buffer for everything
    struct nova_user2lkm *info = (void *) buf;
//     FILE *fp;
    int fd;
    if (argc < 2) {
        printf("use %s [enable, disable, setnid nid, setmpid mpid, setnidmpid nid mpid]\n", argv[0]);
        return 4;
    }

    if(strcmp(argv[1], "enable") == 0){
        info->order = NOVA_U2L_LKM_STATUS;
        info->len = sizeof(int32_t);
        *((int32_t *)info->value) = 1;
    }
    else if(strcmp(argv[1], "disable") == 0){
        info->order = NOVA_U2L_LKM_STATUS;
        info->len = sizeof(int32_t);
        *((int32_t *)info->value) = 0;
    }
    else if(strcmp(argv[1], "setnid") == 0 && argc >= 3){
        info->order = NOVA_U2L_NOVA_ID;
        info->nova_id = atoi(argv[2]);
    }
    else if(strcmp(argv[1], "setmpid") == 0 && argc >= 3){
        info->order = NOVA_U2L_MONITOR_PID;
        info->monitor_pid = atoi(argv[2]);
    }
    else if(strcmp(argv[1], "setnidmpid") == 0 && argc >= 4){
        info->order = NOVA_U2L_NOVA_ID_N_MONITOR_PID;
        info->nova_id = atoi(argv[2]);
        info->monitor_pid = atoi(argv[3]);
    }
    else {
        printf("Nice try\n");
        return 1;
    }

    fd = open("/proc/" LKM_INTERFACE_FILE_PROC, O_WRONLY);
    if(!fd) {
        printf("Cannot open interface file\n");
        return 3;
    }
    write(fd, buf, sizeof(buf));
    close(fd);
    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "nova_uapi.h"

static int write_to_file(struct nova_user2lkm *info) {
    int fd;
    if(!info) return -1;
    fd = open("/proc/" LKM_INTERFACE_FILE_PROC, O_WRONLY);
    if(fd <= 0) {
        printf("Cannot open interface file\n");
        return -1;
    }
    int ret = write(fd, info, sizeof(struct nova_user2lkm));
    close(fd);
    return ret;
}

int nova_setpid(pid_t pid) {
    struct nova_user2lkm info;
    info.order = NOVA_U2L_SET_PID;
    info.pid = pid;
    return write_to_file(&info);
}

int nova_enable() {
    struct nova_user2lkm info;
    info.order = NOVA_U2L_ENABLE;
    return write_to_file(&info);
}

int nova_disable() {
    struct nova_user2lkm info;
    info.order = NOVA_U2L_DISABLE;
    return write_to_file(&info);
}

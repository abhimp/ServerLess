#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "nova_uapi.h"
#include "nova_userland.h"

static int writeToFile(struct nova_user2lkm *info) {
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

int novaSetNid(nova_id_t nid) {
    struct nova_user2lkm info = {
        .order = NOVA_U2L_SET_NOVA_ID,
        .nova_id = nid
    };
    return writeToFile(&info);
}

int novaSetMpid(pid_t mpid) {
    struct nova_user2lkm info = {
        .order = NOVA_U2L_SET_MONITOR_PID,
        .monitor_pid = mpid
    };
    return writeToFile(&info);
}

int novaSetNidMpid(nova_id_t nid, pid_t mpid) {
    struct nova_user2lkm info = {
        .order = NOVA_U2L_SET_NOVA_ID_N_MONITOR_PID,
        .nova_id = nid,
        .monitor_pid = mpid
    };
    return writeToFile(&info);
}

int novaEnable() {
    struct nova_user2lkm info;
    info.order = NOVA_U2L_ENABLE;
    return writeToFile(&info);
}

int novaDisable() {
    struct nova_user2lkm info;
    info.order = NOVA_U2L_DISABLE;
    return writeToFile(&info);
}

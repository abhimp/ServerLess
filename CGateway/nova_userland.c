#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "nova_uapi.h"
#include "nova_userland.h"

static int writeToFile(void *info, size_t infoLen) {
    int fd;
    if(!info) {
        printf("Info is null nova_userland\n");
        return -1;
    }
    fd = open("/proc/" LKM_INTERFACE_FILE_PROC, O_WRONLY);
    if(fd <= 0) {
        printf("Cannot open interface file\n");
        return -1;
    }
    int ret = write(fd, info, infoLen);
    close(fd);
    return ret;
}

int novaSetNid(nova_id_t nid) {
    struct nova_user2lkm info = {
        .order = NOVA_U2L_NOVA_ID,
        .nova_id = nid
    };
    return writeToFile(&info, sizeof(struct nova_user2lkm));
}

int novaSetMpid(pid_t mpid) {
    struct nova_user2lkm info = {
        .order = NOVA_U2L_MONITOR_PID,
        .monitor_pid = mpid
    };
    return writeToFile(&info, sizeof(struct nova_user2lkm));
}

int novaSetNidMpid(nova_id_t nid, pid_t mpid) {
    struct nova_user2lkm info = {
        .order = NOVA_U2L_NOVA_ID_N_MONITOR_PID,
        .nova_id = nid,
        .monitor_pid = mpid
    };
    return writeToFile(&info, sizeof(struct nova_user2lkm));
}

int novaEnable() {
    char buf[sizeof(struct nova_user2lkm) + sizeof(int32_t)]; //enought buffer for everything
    struct nova_user2lkm *info = (void *)buf;
    info->order = NOVA_U2L_LKM_STATUS;
    info->len = sizeof(int32_t);
    *((int32_t *)info->value) = 1;
    return writeToFile(buf, sizeof(buf));
}

int novaDisable() {
    char buf[sizeof(struct nova_user2lkm) + sizeof(int32_t)]; //enought buffer for everything
    struct nova_user2lkm *info = (void *)buf;
    info->order = NOVA_U2L_LKM_STATUS;
    info->len = sizeof(int32_t);
    *((int32_t *)info->value) = 0;
    return writeToFile(buf, sizeof(buf));
}

int novaSetScratchDir(char scratchdir[]) {
    int i;
    char buf[sizeof(struct nova_user2lkm) + strlen(scratchdir) + 1];
    struct nova_user2lkm *info = (void *)buf;
    info->order = NOVA_U2L_NOVA_HOME;
    info->len = strlen(scratchdir) + 1;
    for(i = 0; i<strlen(scratchdir) + 1; i++)
        buf[sizeof(struct nova_user2lkm) + i] = scratchdir[i];
    // buf[strlen(buf)-1] = '\0';
    char *path = info->value;

    printf("Sending %s from nova userland with size %ld\n", path, strlen(scratchdir) + 1);
    return writeToFile(buf, sizeof(buf));
}
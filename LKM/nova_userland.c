#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "nova_uapi.h"

int main(int argc, char *argv[]) {
    struct nova_user2lkm info;
//     FILE *fp;
    int fd;
    if (argc < 2) {
        printf("use %s [enable, disable, setppid pid]\n", argv[0]);
        return 4;
    }

    if(strcmp(argv[1], "enable") == 0){
        info.order = NOVA_U2L_ENABLE;
    }
    else if(strcmp(argv[1], "disable") == 0){
        info.order = NOVA_U2L_DISABLE;
    }
    else if(strcmp(argv[1], "setppid") == 0 && argc >= 3){
        info.order = NOVA_U2L_SET_PID;
        info.pid = atoi(argv[2]);
    }
    else {
        printf("Nice try\n");
        return 1;
    }
//     fp = fopen("/proc/" LKM_INTERFACE_FILE_PROC, "w");
//     if(!fp) {
//         printf("Cannot open interface file\n");
//         return 3;
//     }
//     fwrite(&info, sizeof(info), 1, fp);
//     fclose(fp);

    fd = open("/proc/" LKM_INTERFACE_FILE_PROC, O_WRONLY);
    if(!fd) {
        printf("Cannot open interface file\n");
        return 3;
    }
    write(fd, &info, sizeof(info));
    close(fd);
    return 0;
}

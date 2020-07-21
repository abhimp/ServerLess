/*
 * example.c
 *
 *  Created on: Jul 19, 2020
 *      Author: abhijit
 */

#include <stdio.h>

#include "libncgim.h"

extern char **environ;

void handle(void) {
    printf("HTTP/1.0 200 OK\r\n");
    printf("Content-Type: text/plain\r\n");
    printf("\r\n");
    printf("This is test script\n");
    for(int i = 0; environ[i]; i++) {
        printf("%s\n", environ[i]);
    }
}

int main() {
//    void *info = ncgimInitServer();
    ncgimRunForever(handle);
}

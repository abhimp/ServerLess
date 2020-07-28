/*
 * example.c
 *
 *  Created on: Jul 19, 2020
 *      Author: abhijit
 */

#include <stdio.h>

void nova_func_start(void) {
    printf("HTTP/1.0 200 OK\r\n");
    printf("Content-Type: text/html\r\n");
    printf("\r\n");

    printf("<html>");
    printf("<head><title>Hello Nova</title></head>");
    printf("<body><h1>HELLO NOVA</h1></body>");
    printf("</html>");
}


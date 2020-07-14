#ifndef __NOVA_USERLAND_H__
#define __NOVA_USERLAND_H__

#include <unistd.h>
int novaSetpid(pid_t pid);

int novaEnable();

int novaDisable();
#endif

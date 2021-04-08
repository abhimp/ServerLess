#ifndef __NOVA_USERLAND_H__
#define __NOVA_USERLAND_H__

#include "nova_uapi.h"
int novaSetNid(nova_id_t nid);

int novaSetMpid(pid_t mpid);

int novaSetNidMpid(nova_id_t nid, pid_t mpid);

int novaEnable();

int novaDisable();

int novaSetScratchDir(char scratchdir[]);
#endif

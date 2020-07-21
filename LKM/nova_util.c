#define NOVA_REDIRECT_SOURCE
#include "kern_version_adjustment.h"
#include "nova_util.h"

static long functionRedirected = 0;
static long activeRedirection = 0;
static pid_t monitorPid = 0;
DECLARE_NOVA_ID();


static sys_call_ptr_t orig_systemcall_table[NOVA_max_syscalls] = {
    [0 ... NOVA_max_syscalls-1] = NULL
};



//These are no ordinary includes. These section have to stay here.
//One should not push it up or down.
//==================================================
#include "nova_funcs.h"
#include "nova_syscall.h"
//==================================================

long novaGetNumFunctionRedirected(void) {
    return functionRedirected;
}

long novaGetActiveRedirections(void) {
    return activeRedirection;
}

void novaSetMonitorPid(pid_t mpid) {
    if(mpid <= 2) return;
    monitorPid = mpid;
}

pid_t novaGetMonitorPid(void) {
    return monitorPid;
}

void novaSetNovaId(nova_id_t nid) {
    if (nid <= 2) return;
    SET_NOVA_ID(nid);
}

nova_id_t novaGetNovaId(void) {
    return GET_NOVA_ID();
}

void novaStoreOrigSysCall(int x, sys_call_ptr_t *y) {
    NOVA_STORE_ORIG(x, y);
}

void novaRedirectSysCall(int x, sys_call_ptr_t *y) {
    if(CAN_REDIRECT_BASED_ON_NOVA_ID()) { //TODO replace with better MACRO
        NOVA_REDIRECT(x, y);
    }
}

void novaRestoreSysCall(int x, sys_call_ptr_t *y) {
    NOVA_RESTORE(x, y);
}

void novaStoreAllOrigSysCalls(sys_call_ptr_t *y) {
    int i;
    int numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);
    for(i = 0; i < numHandled; i++) {
        NOVA_STORE_ORIG(nova_handled_syscals[i], y);
    }
}

void novaRedirectAllSysCalls(sys_call_ptr_t *y) {
    int i;
    if(CAN_REDIRECT_BASED_ON_NOVA_ID()) {
        int numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);
        for(i = 0; i < numHandled; i++) {
            NOVA_REDIRECT(nova_handled_syscals[i], y);
        }
    }
}

void novaRestoreAllSysCall(sys_call_ptr_t *y) {
    int i;
    int numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);
    for(i = 0; i < numHandled; i++) {
        NOVA_RESTORE(nova_handled_syscals[i], y);
    }
}


void novaInitVerifier(void) {
}

#define NOVA_REDIRECT_SOURCE
#include "kern_version_adjustment.h"
#include "nova_util.h"

static long functionRedirected = 0;
static long activeRedirection = 0;
static pid_t nova_ppid = 0;


static sys_call_ptr_t orig_systemcall_table[NOVA_max_syscalls] = {
    [0 ... NOVA_max_syscalls-1] = NULL
};

static void *verify_systemcall_table[NOVA_max_syscalls] = {
    [0 ... NOVA_max_syscalls-1] = NULL
};


#include "nova_syscall.h"

long novaGetNumFunctionRedirected(void) {
    return functionRedirected;
}

long novaGetActiveRedirections(void) {
    return activeRedirection;
}

void novaSetPPid(pid_t pid) {
    if (pid <= 2) return;
    nova_ppid = pid;
}

void novaStoreOrigSysCall(int x, sys_call_ptr_t *y) {
    NOVA_STORE_ORIG(x, y);
}

void novaRedirectSysCall(int x, sys_call_ptr_t *y) {
    if(nova_ppid >= 2) {
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
    if(nova_ppid >= 2) {
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



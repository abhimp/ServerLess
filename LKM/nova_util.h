#ifndef __NOVA_SYS_CALL_REDIRECT__
#define __NOVA_SYS_CALL_REDIRECT__
#include <linux/syscalls.h>

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);

#define NOVA_max_syscalls 512 //it was hard to find a header which define it

#define NOVA_STORE_ORIG(x, y) { \
	if(y[x] != nova_syscall_table[x]) {\
		orig_systemcall_table[x] = y[x]; \
	}\
}

#define NOVA_REDIRECT(x, y) { \
	if(y[x] != nova_syscall_table[x]) {\
		y[x] = nova_syscall_table[x]; \
	}\
}

#define NOVA_RESTORE(x, y) { \
	if(NULL != orig_systemcall_table[x]) {\
		y[x] = orig_systemcall_table[x]; \
	}\
}

#define RESET_COUNTER functionRedirected=0

#ifndef NOVA_REDIRECT_SOURCE
#endif

long novaGetNumFunctionRedirected(void);
long novaGetActiveRedirections(void);
void novaSetPPid(pid_t pid);
pid_t novaGetPPid(void);
void novaStoreOrigSysCall(int x, sys_call_ptr_t *y);
void novaRedirectSysCall(int x, sys_call_ptr_t *y);
void novaRestoreSysCall(int x, sys_call_ptr_t *y);
void novaStoreAllOrigSysCalls(sys_call_ptr_t *y);
void novaRedirectAllSysCalls(sys_call_ptr_t *y);
void novaRestoreAllSysCall(sys_call_ptr_t *y);
void novaInitVerifier(void);

#endif


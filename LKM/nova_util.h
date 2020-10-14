#ifndef __NOVA_SYS_CALL_REDIRECT__
#define __NOVA_SYS_CALL_REDIRECT__
#include <linux/syscalls.h>

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);

typedef gid_t nova_id_t;
typedef kgid_t nova_kid_t;


#define NOVA_ID_NAME() nova_iso_gpid
#define DECLARE_NOVA_ID() static nova_kid_t NOVA_ID_NAME()
#define GET_NOVA_ID() from_kgid(current_user_ns(), NOVA_ID_NAME())
#define SET_NOVA_ID(x) NOVA_ID_NAME() = make_kgid(current_user_ns(), x)
#define IS_SAME_AS_NOVA_ID(x) gid_eq(x, NOVA_ID_NAME())
#define CAN_REDIRECT_BASED_ON_NOVA_ID() (GET_NOVA_ID() >= 2)
#define CAN_REDIRECT_NOVA() (novaGetNovaId() >= 2)

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

#define RESET_COUNTER functionRedirected = 0

#ifndef NOVA_REDIRECT_SOURCE
#endif

long novaGetNumFunctionRedirected(void);
long novaGetActiveRedirections(void);
void novaSetMonitorPid(pid_t mpid);
pid_t novaGetMonitorPid(void);
void novaSetNovaId(nova_id_t nid);
nova_id_t novaGetNovaId(void);
int novaSetHomePath(const char *path, size_t count);

void novaStoreOrigSysCall(int x, sys_call_ptr_t *y);
void novaRedirectSysCall(int x, sys_call_ptr_t *y);
void novaRestoreSysCall(int x, sys_call_ptr_t *y);
void novaStoreAllOrigSysCalls(sys_call_ptr_t *y);
void novaRedirectAllSysCalls(sys_call_ptr_t *y);
void novaRestoreAllSysCall(sys_call_ptr_t *y);
void novaInitVerifier(void);

#endif


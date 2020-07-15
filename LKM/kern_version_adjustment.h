#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)
#define __kernel_old_timeval timeval
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,1,0)
#define __kernel_timex timex
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
#define __kernel_timespec timespec
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
#define __kernel_itimerspec itimerspec
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,6)
#define __kernel_old_itimerval itimerval
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,6)
#define __kernel_old_time_t time_t
#endif

// # include <asm/ldt.h>

#if defined __i386__ || defined __x86_64__
// # include <asm/ldt.h>

#elif defined __m68k__

// int get_thread_area(void);
// int set_thread_area(unsigned long tp);

#elif defined __mips__

// int set_thread_area(unsigned long addr);

#endif


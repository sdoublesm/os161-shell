#include <kern/unistd.h>
#include <kern/errno.h>
#include <kern/wait.h>
#include <kern/fcntl.h>
#include <kern/syscall.h>

#include <types.h>
#include <lib.h>
#include <copyinout.h>
#include <clock.h>
#include <thread.h>
#include <current.h>
#include <addrspace.h>
#include <proc.h>
#include <vnode.h>
#include <vfs.h>
#include <uio.h>
#include <stat.h>
#include <syscall.h>
#include <synch.h>

pid_t sys_getpid(void){
#if OPT_SHELLPROJECT
    KASSERT(curproc != NULL);
    return curproc->p_id;
#else
    return -1;
#endif
}

void sys__exit(int exitcode){
#if OPT_SHELLPROJECT
    struct proc *p = curproc;
    p->exit_code = exitcode & 0xff;
    proc_remthread(curthread);

    lock_acquire(p->p_lock);
    cv_signal(p->p_cv, p->p_lock);
    lock_release(p->p_lock);
#else
    struct addrspace *as = proc_getas();
    as_destroy(as);
#endif
    thread_exit();
    panic("thread_exit returned (should not happen)\n");
    (void) exitcode;
}

int sys_waitpid(pid_t pid, int *status, int options){
#if OPT_SHELLPROJECT
    struct proc *p = proc_search_pid(pid);
    int s;
    (void) options;
    if (p == NULL) return -1;
    s = proc_wait(p);
    if (status != NULL)
        *(int *) status = s;
    return pid;
#else
    (void) options;
    (void) pid;
    (void) status;
    return -1;
#endif
}
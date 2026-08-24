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
#include <../../userland/include/errno.h>
#include <mips/trapframe.h>

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
    p->exit_status = exitcode & 0xff;
    p->has_exited = true;
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
    KASSERT(curproc != NULL);

    // cannot wait on itself
    // if so, error ECHILD
    if (pid == curproc->p_id){
        errno = ECHILD;
        return -1;
    }

    // cannot wait on a process which is not its child
    // if so, error ECHILD
    if (!check_child(curproc, pid)){
        errno = ECHILD;
        return -1;
    }

    // the status pointer has to be addressed to a multiple of 4 address
    // if not (so it is unaligned), it cannot contain an integer, so error EFAULT
    if ((vaddr_t) status % 4 != 0){
        errno = EFAULT;
        return -1;
    }

    // let's find the process, if it doesn't exist, error EINVAL
    struct proc *p = proc_search_pid(pid);
    if (p == NULL){
        errno = ESRCH;
        return -1;
    }

    // different values for options. It should be 0, but some options could be implemented
    // here for example WNOHANG is implemented
    // if wrong value of options is given, error EINVAL
    switch (options){
        case 0:
            break;
        case WNOHANG:
            if (!(p->has_exited))
                return 0;
            break;
        default:
            errno = EINVAL;
            return -1;
            break;
    }

    int s;

    // let's wait the process exit
    // if it has already exited, return immediately
    if (!(p->has_exited)){
        s = proc_wait(p);
    }
    if (status != NULL){
        int err = copyout(&s, (userptr_t) status, sizeof(int));
        if (err){
            errno = err;    // err should be automatically EFAULT if it was an invalid pointer
            return -1;
        }
    }

    proc_destroy(p);

    return pid;
#else
    (void) options;
    (void) pid;
    (void) status;
    return -1;
#endif
}

static void call_enter_forked_process(void *tfv, unsigned long dummy){
#if OPT_SHELLPROJECT
	struct trapframe *tf = (struct trapframe *) tfv;
	(void) dummy;

	enter_forked_process(tf);

	panic("enter_forked_process returned (should not happen)");
#else
	(void) tfv;
	(void) dummy;
#endif
}

int sys_fork(struct trapframe *ctf){
#if OPT_SHELLPROJECT
    struct trapframe *tf_child;
    struct proc *cp;
    int result;

    KASSERT(curproc != NULL);

    if (!proc_find_free_slot()){
        errno = ENPROC;
        return -1;
    }

    cp = proc_create_runprogram(curproc->p_name);
    if (cp == NULL){
        errno = ENOMEM;
        return -1;
    }

    as_copy(curproc->p_addrspace, &(cp->p_addrspace));
    if (cp->p_addrspace == NULL){
        proc_destroy(cp);
        errno = ENOMEM;
        return -1;
    }

    tf_child = kmalloc(sizeof(struct trapframe));
    if (tf_child == NULL){
        proc_destroy(cp);
        errno = ENOMEM;
        return -1;
    }
    memcpy(tf_child, ctf, sizeof(struct trapframe));

    // For Mirko: insert here the procedure for copying the file descriptors

    if (proc_insert_child_in_parent(curproc, cp->p_id) == -1){
        proc_destroy(cp);
        errno = ENOMEM;
        return -1;
    }
    cp->parent_id = curproc->p_id;

    result = thread_fork(curthread->t_name, cp, call_enter_forked_process, (void *) tf_child, (unsigned long) 0);
    if (result){
        proc_destroy(cp);
        kfree(tf_child);
        errno = ENOMEM;
        return -1;
    }

    return cp->p_id;
#else
    (void) ctf;
#endif
}
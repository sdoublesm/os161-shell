#include <kern/unistd.h>
#include <kern/errno.h>
#include <kern/wait.h>
#include <kern/syscall.h>

#include <types.h>
#include <kern/fcntl.h>
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
    return ENOSYS;
#endif
}

void sys__exit(int exitcode){
#if OPT_SHELLPROJECT
    struct proc *p = curproc;
    p->exit_status = exitcode & 0xff;
    p->has_exited = true;

    lock_acquire(p->p_lk);
    cv_signal(p->p_cv, p->p_lk);
    lock_release(p->p_lk);

    for (int i = 0; i < OPEN_MAX; i++){
        if (curproc->fileTable[i] != NULL){
            lock_acquire(curproc->fileTable[i]->lk);
            curproc->fileTable[i]->ref_count--;

            if (curproc->fileTable[i]->ref_count > 0) lock_release(curproc->fileTable[i]->lk);
            else{
                lock_release(curproc->fileTable[i]->lk);
                vfs_close(curproc->fileTable[i]->vn);
                lock_destroy(curproc->fileTable[i]->lk);
                kfree(curproc->fileTable[i]);
            }
            curproc->fileTable[i] = NULL;
        }
    }

    struct addrspace *as = proc_setas(NULL);
    as_deactivate();
    if (as != NULL) as_destroy(as);
#else
    struct addrspace *as = proc_getas();
    as_destroy(as);
#endif
    thread_exit();
    panic("thread_exit returned (should not happen)\n");
    (void) exitcode;
}

int sys_waitpid(pid_t pid, int *status, int options, int32_t *retval){
#if OPT_SHELLPROJECT
    KASSERT(curproc != NULL);

    // cannot wait on itself
    // if so, error ECHILD
    if (pid == curproc->p_id) return ECHILD;

    // cannot wait on a process which is not its child
    // if so, error ECHILD
    if (!proc_check_child(curproc, pid)) return ECHILD;

    // the status pointer has to be addressed to a multiple of 4 address
    // if not (so it is unaligned), it cannot contain an integer, so error EFAULT
    if (status != NULL && ((vaddr_t) status % 4 != 0)) return EFAULT;

    // let's find the process, if it doesn't exist, error EINVAL
    struct proc *p = proc_search_pid(pid);
    if (p == NULL) return ESRCH;

    // different values for options. It should be 0, but some options could be implemented
    // here for example WNOHANG is implemented
    // if wrong value of options is given, error EINVAL
    switch (options){
        case 0:
            break;
        case WNOHANG:
            if (!(p->has_exited)){
                *retval = 0;
                return 0;
            }
            break;
        default:
            return EINVAL;
            break;
    }

    int s;

    // let's wait the process exit
    s = proc_wait(p);
    if (status != NULL){
        s = _MKWAIT_EXIT(s);
        int err = copyout(&s, (userptr_t) status, sizeof(int));
        if (err){
            proc_destroy(p);
            return err;         // err should be automatically EFAULT if it was an invalid pointer
        };
    }
    *retval = p->p_id;

    proc_destroy(p);

    return 0;
#else
    (void) options;
    (void) pid;
    (void) status;
    return ENOSYS;
#endif
}

static void call_enter_forked_process(void *tfv, unsigned long dummy){
#if OPT_SHELLPROJECT
	struct trapframe *tf = (struct trapframe *) tfv;
	(void) dummy;

    kfree(tfv);

	enter_forked_process(tf);

	panic("enter_forked_process returned (should not happen)");
#else
	(void) tfv;
	(void) dummy;
#endif
}

int sys_fork(struct trapframe *ctf, pid_t *retval){
#if OPT_SHELLPROJECT
    struct trapframe *tf_child;
    struct proc *cp;
    int result;

    KASSERT(curproc != NULL);

    if (!proc_find_free_slot()) return ENPROC;

    cp = proc_create_runprogram(curproc->p_name);
    if (cp == NULL) return ENOMEM;

    as_copy(curproc->p_addrspace, &(cp->p_addrspace));
    if (cp->p_addrspace == NULL){
        proc_destroy(cp);
        return ENOMEM;
    }

    tf_child = kmalloc(sizeof(struct trapframe));
    if (tf_child == NULL){
        proc_destroy(cp);
        return ENOMEM;
    }
    memcpy(tf_child, ctf, sizeof(struct trapframe));

    // For Mirko: insert here the procedure for copying the file descriptors

    if (proc_insert_child_in_parent(curproc, cp->p_id) == -1){
        kfree(tf_child);
        proc_destroy(cp);
        return ENOMEM;
    }
    cp->parent_id = curproc->p_id;

    result = thread_fork(curthread->t_name, cp, call_enter_forked_process, (void *) tf_child, (unsigned long) 0);
    if (result){
        proc_remove_child_from_parent(curproc, cp->p_id);
        proc_destroy(cp);
        kfree(tf_child);
        return ENOMEM;
    }

    *retval = cp->p_id;
    return 0;
#else
    (void) ctf;
    return ENOSYS;
#endif
}

int sys_execv(const char *program, char **args){
#if OPT_SHELLPROJECT
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;

    if (program == NULL || args == NULL) return EFAULT;

    // safe copy of the program name from user space to kernel space
    char *kern_prog = (char *) kmalloc(PATH_MAX * sizeof(char));
    if (kern_prog == NULL){
        return ENOMEM;
    }
    result = copyinstr((userptr_t) program, kern_prog, PATH_MAX, NULL);
    if (result){
        kfree(kern_prog);
        return result;
    }

    // safe copy of the args array from user space to kernel space
    userptr_t temp_ptr;
    int argc = 0;
    int total_bytes = 0;
    // first we have to count exactly how many arguments we have
    while(1){
        result = copyin((userptr_t)args + (argc*sizeof(userptr_t)), &temp_ptr, sizeof(userptr_t));
        if (result){
            kfree(kern_prog);
            return result;
        }
        if (temp_ptr == NULL) break;
        argc++;
    }
    if (argc == 0){
        kfree(kern_prog);
        return EINVAL;
    }

    total_bytes += (argc+1) * sizeof(char *);

    // now we can actually allocate space for the arguments and copy them
    char *arg_buffer = (char *) kmalloc(ARG_MAX);
    if (arg_buffer == NULL){
        kfree(kern_prog);
        return ENOMEM;
    }

    size_t *arg_offsets = (size_t *) kmalloc(argc * sizeof(size_t));
    if (arg_offsets == NULL){
        kfree(arg_buffer);
        kfree(kern_prog);
        return ENOMEM;
    }
    size_t total_offset = 0;

    for (int i = 0; i < argc; i++){
        userptr_t str_ptr;
        result = copyin((userptr_t) args + (i * sizeof(userptr_t)), &str_ptr, sizeof(userptr_t));
        if (result){
            kfree(arg_offsets);
            kfree(arg_buffer);
            kfree(kern_prog);
            return result;
        }

        size_t actual_length;
        result = copyinstr(str_ptr, arg_buffer + total_offset, ARG_MAX - total_offset, &actual_length);
        if (result){
            kfree(arg_offsets);
            kfree(arg_buffer);
            kfree(kern_prog);
            if (result == ENAMETOOLONG) return E2BIG;
            return result;
        }
        
        arg_offsets[i] = total_offset;
        total_offset += actual_length;
    }

	/* Open the file. */
	result = vfs_open(kern_prog, O_RDONLY, 0, &v);
	if (result) {
        kfree(arg_offsets);
        kfree(arg_buffer);
        kfree(kern_prog);
        return result;
	}

    struct addrspace *old_as;
    struct addrspace *new_as;

    // let's now create the new address space
    new_as = as_create();
    if (new_as == NULL){
        vfs_close(v);
        kfree(arg_offsets);
        kfree(arg_buffer);
        kfree(kern_prog);
        return ENOMEM;
    }

    // we save the old address space for later destruction
    old_as = proc_getas();

    // we switch to the new as and activate it
    proc_setas(new_as);
    as_activate();

    /* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		vfs_close(v);
        kfree(arg_offsets);
        kfree(arg_buffer);
        kfree(kern_prog);
		return result;
	}

    vfs_close(v);

    // we create the user's stack in the new as
    result = as_define_stack(new_as, &stackptr);
    if (result) {
        kfree(arg_offsets);
        kfree(arg_buffer);
        kfree(kern_prog);
		return result;
	}

    // destruction of the old as
    if (old_as != NULL) as_destroy(old_as);

    // first we have to make space in the user stack enough to insert all the arguments
    // we will save each of these address because later we will have to insert them too as pointers in the stack
    // because thei will be the values of the user's argv
    userptr_t *string_addr = kmalloc(argc * sizeof(userptr_t));
    if (string_addr == NULL){
        kfree(arg_offsets);
        kfree(arg_buffer);
        kfree(kern_prog);
        return ENOMEM;
    }
    for (int i = 0; i < argc; i++){
        char *curr_str = arg_buffer + arg_offsets[i];
        int len = strlen(curr_str) + 1;
        stackptr -= len;
        result = copyout(curr_str, (userptr_t) stackptr, len);
        if (result){
            kfree(arg_offsets);
            kfree(arg_buffer);
            kfree(kern_prog);
            kfree(string_addr);
            return result;
        }
        string_addr[i] = (userptr_t) stackptr;
    }

    stackptr -= (stackptr % 8);
    int pointer_array_size = (argc + 1) * sizeof(userptr_t);
    if ((stackptr - pointer_array_size) % 8 != 0) stackptr -= 4;

    char *null_ptr = NULL;
    stackptr -= sizeof(userptr_t);
    result = copyout(&null_ptr, (userptr_t) stackptr, sizeof(char *));
    if (result){
        kfree(arg_offsets);
        kfree(arg_buffer);
        kfree(kern_prog);
        kfree(string_addr);
        return result;
    }
    for (int i = argc-1; i >= 0; i--){
        stackptr -= 4;
        result = copyout(&string_addr[i], (userptr_t) stackptr, sizeof(userptr_t));
        if (result){
            kfree(arg_offsets);
            kfree(arg_buffer);
            kfree(kern_prog);
            kfree(string_addr);
            return result;
        }
    }

    kfree(arg_offsets);
    kfree(arg_buffer);
    kfree(kern_prog);
    kfree(string_addr);

	/* Warp to user mode. */
	enter_new_process(argc /*argc*/, (userptr_t) stackptr /*userspace addr of argv*/,
			  NULL /*userspace addr of environment*/,
			  stackptr, entrypoint);

	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL;
#else
    (void) program;
    (void) args;
    return ENOSYS;
#endif
}
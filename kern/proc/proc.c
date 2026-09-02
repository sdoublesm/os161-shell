/*
 * Copyright (c) 2013
 *	The President and Fellows of Harvard College.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE UNIVERSITY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Process support.
 *
 * There is (intentionally) not much here; you will need to add stuff
 * and maybe change around what's already present.
 *
 * p_lock is intended to be held when manipulating the pointers in the
 * proc structure, not while doing any significant work with the
 * things they point to. Rearrange this (and/or change it to be a
 * regular lock) as needed.
 *
 * Unless you're implementing multithreaded user processes, the only
 * process that will have more than one thread is the kernel process.
 */

#include <types.h>
#include <spl.h>
#include <proc.h>
#include <current.h>
#include <addrspace.h>
#include <vnode.h>

#if OPT_SHELLPROJECT
#include <synch.h>
#define MAX_PROC 100

static struct _processTable{
	int active;
	struct proc *proc[MAX_PROC+1];
	int last_i;
	struct spinlock lk;
}processTable;
#endif

/*
 * The process for the kernel; this holds all the kernel-only threads.
 */
struct proc *kproc;

bool proc_find_free_slot(void){
#if OPT_SHELLPROJECT
	int curr = processTable.last_i + 1;
	if (curr > MAX_PROC) curr = 1;
	while (curr != processTable.last_i){
		if (processTable.proc[curr] == NULL) return true;

		curr++;
		if (curr > MAX_PROC) curr = 1;
	}

	return false;
#else
	return false;
#endif
}

struct proc * proc_search_pid(pid_t pid){
#if OPT_SHELLPROJECT
	if (pid <= 0 || pid > MAX_PROC) return NULL;

	struct proc *p;

	p = processTable.proc[pid];

	if (p->p_id != pid) return NULL;
	
	return p;
#else
	(void) pid;
	return NULL;
#endif
}

int proc_clear_children_list(struct proc *parent){
#if OPT_SHELLPROJECT
	struct child_node *curr;
	struct proc *child;
	struct child_node *next;

	spinlock_acquire(&parent->p_lock);
	curr = parent->children_list;
	parent->children_list = NULL;
	spinlock_release(&parent->p_lock);

	while (curr != NULL){
		next = curr->next;

		child = proc_search_pid(curr->c_pid);
		if (child != NULL){
			spinlock_acquire(&child->p_lock);
			child->parent_id = -1;
			spinlock_release(&child->p_lock);
		}
		kfree(curr);

		curr = next;
	}

	return 0;
#else
	(void) parent;
	return -1;
#endif
}

int proc_insert_child_in_parent(struct proc *parent, pid_t c_pid){
#if OPT_SHELLPROJECT
	struct child_node *new = (struct child_node *) kmalloc(sizeof(struct child_node));
	if (new == NULL) return -1;

	new->c_pid = c_pid;
	new->next = NULL;

	spinlock_acquire(&parent->p_lock);
	if (parent->children_list == NULL)
		parent->children_list = new;
	else{
		struct child_node *curr = parent->children_list;
		while (curr->next != NULL) curr = curr->next;
		curr->next = new;
	}

	spinlock_release(&parent->p_lock);
	return 0;
#else
	(void) parent;
	(void) c_pid;
	return -1;
#endif
}

int proc_remove_child_from_parent(struct proc *parent, pid_t c_pid){
#if OPT_SHELLPROJECT
	struct child_node *curr;
	struct child_node *prev = NULL;
	struct child_node *to_free = NULL;

	spinlock_acquire(&parent->p_lock);
	curr = parent->children_list;
	while (curr != NULL){
		if (curr->c_pid == c_pid){
			if (prev == NULL)
				parent->children_list = curr->next;
			else
				prev->next = curr->next;

			to_free = curr;
			break;
		}

		prev = curr;
		curr = curr->next;
	}

	spinlock_release(&parent->p_lock);
	if (to_free != NULL){
		kfree(to_free);
		return 0;
	}
	return -1;
#else
	(void) parent;
	(void) c_id;
	return -1;
#endif
}

void proc_init(struct proc *proc, const char *name){
#if OPT_SHELLPROJECT
	int i;
	if (strcmp(name, "[kernel]") == 0){
		processTable.proc[0] = kproc;
	}
	else{
		spinlock_acquire(&processTable.lk);
		i = processTable.last_i + 1;
		proc->p_id = -1;
		if (i > MAX_PROC) i = 1;	// not from 0 because it is the kernell process
		while (i != processTable.last_i){
			if (processTable.proc[i] == NULL){
				processTable.proc[i] = proc;
				processTable.last_i = i;
				proc->p_id = i;
				break;
			}
			i++;
			if (i > MAX_PROC) i = 1;
		}
		spinlock_release(&processTable.lk);
	}
	if (proc->p_id == -1){
		panic("too many processes. proc table is full \n");
	}
	proc->exit_status = 0;
	proc->has_exited = false;
	proc->parent_id = -1;
	proc->children_list = NULL;
	proc->p_cv = cv_create(name);
	proc->p_lk = lock_create(name);
	for (int j = 0; i < OPEN_MAX; j++) proc->fileTable[j] = NULL;
#else
	(void) proc;
	(void) name;
#endif
}

int proc_end(struct proc *proc){
#if OPT_SHELLPROJECT
	int i;
	spinlock_acquire(&processTable.lk);
	i = proc->p_id;
	KASSERT(i > 0 && i <= MAX_PROC);
	processTable.proc[i] = NULL;
	spinlock_release(&processTable.lk);
	cv_destroy(proc->p_cv);
	lock_destroy(proc->p_lk);

	if (proc_clear_children_list(proc) == -1) return -1;

	if (proc->parent_id != -1){
		struct proc *parent = proc_search_pid(proc->parent_id);

		if (proc->parent_id == kproc->p_id) parent = kproc;

		if (parent == NULL) return -1;

		if (proc_remove_child_from_parent(parent, proc->p_id) == -1) return -1;
	}

	return 0;
#else
	(void) proc;
	return -1;
#endif
}

int proc_wait(struct proc *proc){
#if OPT_SHELLPROJECT
	int return_status;
	KASSERT(proc != NULL);
	KASSERT(proc != kproc);
	lock_acquire(proc->p_lk);
	while (!proc->has_exited) cv_wait(proc->p_cv, proc->p_lk);
	return_status = proc->exit_status;
	lock_release(proc->p_lk);
	return return_status;
#else
	(void) proc;
	return -1;
#endif
}

int proc_check_child(struct proc * parent, pid_t c_pid){
#if OPT_SHELLPROJECT
	struct child_node *curr = parent->children_list;
	while (curr != NULL){
		if (curr->c_pid == c_pid) return 1;
		curr = curr->next;
	}
	return 0;
#else
	(void) parent;
	(void) child_pid;
	return -1;
#endif
}

/*
 * Create a proc structure.
 */
static
struct proc *
proc_create(const char *name)
{
	struct proc *proc;

	proc = kmalloc(sizeof(*proc));
	if (proc == NULL) {
		return NULL;
	}
	proc->p_name = kstrdup(name);
	if (proc->p_name == NULL) {
		kfree(proc);
		return NULL;
	}

	proc->p_numthreads = 0;
	spinlock_init(&proc->p_lock);

	/* VM fields */
	proc->p_addrspace = NULL;

	/* VFS fields */
	proc->p_cwd = NULL;

	proc_init(proc, name);

	return proc;
}

/*
 * Destroy a proc structure.
 *
 * Note: nothing currently calls this. Your wait/exit code will
 * probably want to do so.
 */
void
proc_destroy(struct proc *proc)
{
	/*
	 * You probably want to destroy and null out much of the
	 * process (particularly the address space) at exit time if
	 * your wait/exit design calls for the process structure to
	 * hang around beyond process exit. Some wait/exit designs
	 * do, some don't.
	 */

	KASSERT(proc != NULL);
	KASSERT(proc != kproc);

	/*
	 * We don't take p_lock in here because we must have the only
	 * reference to this structure. (Otherwise it would be
	 * incorrect to destroy it.)
	 */

	/* VFS fields */
	if (proc->p_cwd) {
		VOP_DECREF(proc->p_cwd);
		proc->p_cwd = NULL;
	}

	/* VM fields */
	if (proc->p_addrspace) {
		/*
		 * If p is the current process, remove it safely from
		 * p_addrspace before destroying it. This makes sure
		 * we don't try to activate the address space while
		 * it's being destroyed.
		 *
		 * Also explicitly deactivate, because setting the
		 * address space to NULL won't necessarily do that.
		 *
		 * (When the address space is NULL, it means the
		 * process is kernel-only; in that case it is normally
		 * ok if the MMU and MMU- related data structures
		 * still refer to the address space of the last
		 * process that had one. Then you save work if that
		 * process is the next one to run, which isn't
		 * uncommon. However, here we're going to destroy the
		 * address space, so we need to make sure that nothing
		 * in the VM system still refers to it.)
		 *
		 * The call to as_deactivate() must come after we
		 * clear the address space, or a timer interrupt might
		 * reactivate the old address space again behind our
		 * back.
		 *
		 * If p is not the current process, still remove it
		 * from p_addrspace before destroying it as a
		 * precaution. Note that if p is not the current
		 * process, in order to be here p must either have
		 * never run (e.g. cleaning up after fork failed) or
		 * have finished running and exited. It is quite
		 * incorrect to destroy the proc structure of some
		 * random other process while it's still running...
		 */
		struct addrspace *as;

		if (proc == curproc) {
			as = proc_setas(NULL);
			as_deactivate();
		}
		else {
			as = proc->p_addrspace;
			proc->p_addrspace = NULL;
		}
		as_destroy(as);
	}

	KASSERT(proc->p_numthreads == 0);
	spinlock_cleanup(&proc->p_lock);

	proc_end(proc);

	kfree(proc->p_name);
	kfree(proc);
}

/*
 * Create the process structure for the kernel.
 */
void
proc_bootstrap(void)
{
	kproc = proc_create("[kernel]");
	if (kproc == NULL) {
		panic("proc_create for kproc failed\n");
	}
#if OPT_SHELLPROJECT
	spinlock_init(&processTable.lk);
	processTable.active = 1;
	for (int i = 1; i <= MAX_PROC; i++) processTable.proc[i] = NULL;
	processTable.last_i = 0;
#endif
}

/*
 * Create a fresh proc for use by runprogram.
 *
 * It will have no address space and will inherit the current
 * process's (that is, the kernel menu's) current directory.
 */
struct proc *
proc_create_runprogram(const char *name)
{
	struct proc *newproc;

	newproc = proc_create(name);
	if (newproc == NULL) {
		return NULL;
	}

	/* VM fields */

	newproc->p_addrspace = NULL;

	/* VFS fields */

	/*
	 * Lock the current process to copy its current directory.
	 * (We don't need to lock the new process, though, as we have
	 * the only reference to it.)
	 */
	spinlock_acquire(&curproc->p_lock);
	if (curproc->p_cwd != NULL) {
		VOP_INCREF(curproc->p_cwd);
		newproc->p_cwd = curproc->p_cwd;
	}
	spinlock_release(&curproc->p_lock);

	return newproc;
}

/*
 * Add a thread to a process. Either the thread or the process might
 * or might not be current.
 *
 * Turn off interrupts on the local cpu while changing t_proc, in
 * case it's current, to protect against the as_activate call in
 * the timer interrupt context switch, and any other implicit uses
 * of "curproc".
 */
int
proc_addthread(struct proc *proc, struct thread *t)
{
	int spl;

	KASSERT(t->t_proc == NULL);

	spinlock_acquire(&proc->p_lock);
	proc->p_numthreads++;
	spinlock_release(&proc->p_lock);

	spl = splhigh();
	t->t_proc = proc;
	splx(spl);

	return 0;
}

/*
 * Remove a thread from its process. Either the thread or the process
 * might or might not be current.
 *
 * Turn off interrupts on the local cpu while changing t_proc, in
 * case it's current, to protect against the as_activate call in
 * the timer interrupt context switch, and any other implicit uses
 * of "curproc".
 */
void
proc_remthread(struct thread *t)
{
	struct proc *proc;
	int spl;

	proc = t->t_proc;
	KASSERT(proc != NULL);

	spinlock_acquire(&proc->p_lock);
	KASSERT(proc->p_numthreads > 0);
	proc->p_numthreads--;
	spinlock_release(&proc->p_lock);

	spl = splhigh();
	t->t_proc = NULL;
	splx(spl);
}

/*
 * Fetch the address space of (the current) process.
 *
 * Caution: address spaces aren't refcounted. If you implement
 * multithreaded processes, make sure to set up a refcount scheme or
 * some other method to make this safe. Otherwise the returned address
 * space might disappear under you.
 */
struct addrspace *
proc_getas(void)
{
	struct addrspace *as;
	struct proc *proc = curproc;

	if (proc == NULL) {
		return NULL;
	}

	spinlock_acquire(&proc->p_lock);
	as = proc->p_addrspace;
	spinlock_release(&proc->p_lock);
	return as;
}

/*
 * Change the address space of (the current) process. Return the old
 * one for later restoration or disposal.
 */
struct addrspace *
proc_setas(struct addrspace *newas)
{
	struct addrspace *oldas;
	struct proc *proc = curproc;

	KASSERT(proc != NULL);

	spinlock_acquire(&proc->p_lock);
	oldas = proc->p_addrspace;
	proc->p_addrspace = newas;
	spinlock_release(&proc->p_lock);
	return oldas;
}

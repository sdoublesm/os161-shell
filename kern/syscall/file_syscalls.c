/* 
? How to design	
[ int sys_read(int fd, userptr_t buf, size_t size, int *retval) ]

- To translate the file descriptor number to a file handle object
- To make a uio record: userspace I/O (See kern/include/uio.h)
- To call VOP_READ	
 — update the current seek position.		
 — Prototype: kern/include/vnode.h
 — Sample Code: kern/userprog/loadelf.c
- the file is locked while this occurs

hints from slides:
• Use fd to locate the openfile item from fileTable
• Access offset from openfile
• userio = setup a uio record	
• Call VOP_READ(openfile->vnode, userio)
• Openfile->offset = userio.offset;
• Set *retval to the amount read	

*/

#include <types.h>
#include <kern/errno.h>
#include <kern/fcntl.h>
#include <kern/limits.h>
#include <lib.h>
#include <proc.h>
#include <current.h>
#include <addrspace.h>
#include <vnode.h>
#include <uio.h>
#include <synch.h>
#include <syscall.h>

/*
 * sys_read
 * 
 * int sys_read(int fd, userptr_t buf, size_t size, int *retval)
 */
int sys_read(int fd, userptr_t buf, size_t size, int *retval)
{
//#if OPT_SHELLPROJECT
	struct openfile *file;
	struct iovec iov;
	/** 
	uio (userspace i/o) usato per gestire in sicurezza il trasferimento
	di dati da kernel a processo utente o viceversa 
	non possono essere copiati direttamente tramite memcpy

	all'interno dell'uio vengono usati uno o più iovec
	per dire dove e quanti dati spstare

	uio contiene appunto iovec, il flag per indicare che stiamo scrivendo verso USERSPACE
	e id dell'address space per il processo corrente

	*/
	struct uio userio;
	int result;
	int amode;

	// validity check file descriptor
	if (fd < 0 || fd >= OPEN_MAX) {
		return EBADF;
	}

	// get the openfile item from fileTable
	file = curproc->fileTable[fd];
	if (file == NULL) {
		return EBADF;
	}

	// check mode is compatible with read
	amode = file->mode & O_ACCMODE;
	if (amode == O_WRONLY) {
		return EBADF;
	}

	// acquire lock on file offset
	lock_acquire(file->lk);

	/* set iovec and uio structs for the transfer toward the userspace */
	// set iovec fields
	iov.iov_ubase = buf; // indirizzo base nello userspace dove veranno copiati i dati 
	iov.iov_len = size;
	
	userio.uio_iov = &iov;
	userio.uio_iovcnt = 1;
	userio.uio_offset = file->offset;
	userio.uio_resid = size;
	userio.uio_segflg = UIO_USERSPACE;
	userio.uio_rw = UIO_READ;
	userio.uio_space = proc_getas();

	// ! use VOP_READ function from VFS
	result = VOP_READ(file->vn, &userio);
	if (result) {
		lock_release(file->lk);
		return result;
	}

	// offset update
	file->offset = userio.uio_offset;

	// retval is the number of red bytes
	*retval = size - userio.uio_resid;
	//lock release
	lock_release(file->lk);
	return 0;
//#endif
}

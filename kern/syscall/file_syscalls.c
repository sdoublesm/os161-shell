// ! For any given process, the first file descriptors (0, 1, and 2) are considered to be standard input
// ! (stdin), standard output (stdout), and standard error (stderr). These file descriptors should start
// ! out attached to the console device ("con:")
// la console e' una stream di caratteri, non ha una dimensione
// quindi non è seekable (scorrevole). offset sempre 0

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
#include <kern/stat.h>
#include <kern/seek.h>
#include <stat.h>
#include <copyinout.h>
#include <vfs.h>

/* 
? How to design	
* int sys_read(int fd, userptr_t buf, size_t size, int *retval)
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

int sys_read(int fd, userptr_t buf, size_t size, int *retval)
{
#if OPT_SHELLPROJECT
	struct openfile *file;
	struct lock *ftlock = curproc->p_lk; // file table lock-protected
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
	lock_acquire(ftlock);
	file = curproc->fileTable[fd];
	lock_release(ftlock);

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
	
	if (fd <= 2) {
		userio.uio_offset = 0;
	} else {
		userio.uio_offset = file->offset;
	}
	
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

	// offset update only for regular files
	if (fd > 2) {
		file->offset = userio.uio_offset;
	}

	// retval is the number of red bytes
	*retval = size - userio.uio_resid;
	//lock release
	lock_release(file->lk);
	return 0;
#endif
}


/* 
* int sys_write(int fd, userptr_t buf, size_t size, int *retval)
*/
int sys_write(int fd, userptr_t buf, size_t size, int *retval)
{
#if OPT_SHELLPROJECT
	struct openfile *file;
	struct lock *ftlock = curproc->p_lk;
	struct iovec iov;
	struct uio userio;
	int result;
	int amode;

	if (fd < 0 || fd >= OPEN_MAX) {
		return EBADF;
	}

	lock_acquire(ftlock);
	file = curproc->fileTable[fd];
	lock_release(ftlock);
	if (file == NULL) {
		return EBADF;
	}

	// check file mode is not readonly
	amode = file->mode & O_ACCMODE;
	if (amode == O_RDONLY) {
		return EBADF;
	}

	lock_acquire(file->lk);

	iov.iov_ubase = buf;
	iov.iov_len = size;
	
	userio.uio_iov = &iov;
	userio.uio_iovcnt = 1;

	if (fd <= 2) {
		userio.uio_offset = 0;
	} else {
		userio.uio_offset = file->offset;
	}

	userio.uio_resid = size;
	userio.uio_segflg = UIO_USERSPACE;
	userio.uio_rw = UIO_WRITE;
	userio.uio_space = proc_getas();

	// ! use VOP_WRITE function from VFS
	result = VOP_WRITE(file->vn, &userio);
	if (result) {
		lock_release(file->lk);
		return result;
	}

	if (fd > 2) {
		file->offset = userio.uio_offset;
	}
	*retval = size - userio.uio_resid;

	lock_release(file->lk);
	return 0;
#endif
}

/* 
* int lseek(int fd, off_t offset, int whence, int *retval);

lseek() repositions the file offset of the open file description
associated with the file descriptor fd to the argument offset
according to the directive [whence] as follows:

SEEK_SET
	The file offset is set to offset bytes.

SEEK_CUR
	The file offset is set to its current location plus offset bytes.

SEEK_END
The file offset is set to the size of the file plus offset bytes.

Upon successful completion, lseek() returns the resulting offset
location as measured in bytes from the beginning of the file.  On
error, the value (off_t) -1 is returned and errno is set to
indicate the error.
*/
int sys_lseek(int fd, off_t offset, int whence, int *retval){
#if OPT_SHELLPROJECT
	struct openfile *file = NULL;
	struct lock *ftlock = curproc->p_lk;
	off_t new_offset;
	struct stat stats;
	int result = 0;

	if (fd < 0 || fd >= OPEN_MAX) {
		return EBADF;
	}

	lock_acquire(ftlock);
	file = curproc->fileTable[fd];
	lock_release(ftlock);
	if (file == NULL) {
		return EBADF;
	}

	// check: file is seekable?	
    if (fd <= 2) {
		return ESPIPE; // fd is associated to a pipe, socket or fifo
	}
	// lock per modifica offset
	lock_acquire(file->lk);

	switch (whence) {
		case SEEK_SET:
			new_offset = offset;
			break;
		case SEEK_CUR:
			new_offset = file->offset + offset;
			break;
		case SEEK_END:
		// ! VOP_STAT riempie la struct stats che contiene la grandezza del file 	
		result = VOP_STAT(file->vn, &stats); // ritorna 0 in caso di successo
			if (result) { // error
				lock_release(file->lk);
				return result;
			}
			new_offset = stats.st_size + offset;
			break;
		default:
			lock_release(file->lk);
			return EINVAL;
	}

	// update offset
	if (new_offset < 0) {
		lock_release(file->lk);
		return EINVAL;
	}
	file->offset = new_offset;
	*retval = (int)new_offset;
	lock_release(file->lk);

	return 0; // success
#endif
}

/* 
? How to design	
* sys_open(filename, flags, mode, retfd)?

creates and return the file descriptor

Opens a file: create an openfile item
Obtain vnode from vfs_open()
Initialize offset in openfile
File descriptor fd = Place openfile in	
systemFiletable (Where is the table?)		
Return the file descriptor of the openfile item.	
*/

int sys_open(userptr_t pathname, int flags, mode_t mode, int *retval)
{
#if OPT_SHELLPROJECT
	struct openfile *file;
	struct vnode *vn;
	char filename[PATH_MAX];
	int result;
	size_t actual_len;
	struct lock *ftlock = curproc->p_lk;
	int fd;

	// copy the string from user space to kernel space 
	// necessary to avoid direct access to user memory
	result = copyinstr(pathname, filename, sizeof(filename), &actual_len);
	if (result) {
		return result;
	}

	// ci serve il vnode, si occupa vfs_open di chiamare VOP_OPEN
	result = vfs_open(filename, flags, mode, &vn);
	if (result) {
		return result;
	}
	// allochiamo struct openfile vuota
	file = kmalloc(sizeof(struct openfile));
	if (file == NULL) {
		vfs_close(vn);
		return ENOMEM;
	}

	// init openfile fields
	file->vn = vn;
	file->offset = 0;
	file->mode = flags;
	file->ref_count = 1;
	file->lk = lock_create(filename);
	if (file->lk == NULL) {
		kfree(file);
		vfs_close(vn);
		return ENOMEM;
	}

	// insert openfile at the first free slot inside the filetable
	lock_acquire(ftlock);
	for (fd = 0; fd < OPEN_MAX; fd++) {
		if (curproc->fileTable[fd] == NULL) {
			curproc->fileTable[fd] = file;
			break;
		}
	}
	lock_release(ftlock);
	// no free slot
	if (fd == OPEN_MAX) {
		lock_destroy(file->lk);
		kfree(file);
		vfs_close(vn);
		return EMFILE; // per-process limit on the number of open file reached
	}
	*retval = fd;	
	return 0;
#endif
}
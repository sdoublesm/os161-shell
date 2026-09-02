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

int sys_read(int fd, userptr_t buf, size_t size, int32_t *retval)
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
	int err;
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
	// file->mode in AND with ACCESS MODE (permessi utente)
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
	
	// don't force offset=0 for fd<=2!
	// ad esempio per permettere il redirect dell'I/O (ls > test.txt)
	// che fa close(0) per poi aprire test.txt in una di quelle posizioni
	// il driver della console ignora l'offset in automatico!
	// src/kern/dev/generic/console.c
	userio.uio_offset = file->offset;
	
	userio.uio_resid = size;
	userio.uio_segflg = UIO_USERSPACE;
	userio.uio_rw = UIO_READ;
	userio.uio_space = proc_getas();

	// ! use VOP_READ function from VFS
	err = VOP_READ(file->vn, &userio);
	if (err) {
		lock_release(file->lk);
		return err;
	}

	// offset update
	file->offset = userio.uio_offset;

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
int sys_write(int fd, userptr_t buf, size_t size, int32_t *retval)
{
#if OPT_SHELLPROJECT
	struct openfile *file;
	struct lock *ftlock = curproc->p_lk;
	struct iovec iov;
	struct uio userio;
	int err;
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

	userio.uio_offset = file->offset;

	userio.uio_resid = size;
	userio.uio_segflg = UIO_USERSPACE;
	userio.uio_rw = UIO_WRITE;
	userio.uio_space = proc_getas();

	// ! use VOP_WRITE function from VFS
	err = VOP_WRITE(file->vn, &userio);
	if (err) {
		lock_release(file->lk);
		return err;
	}

	file->offset = userio.uio_offset;
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
int sys_lseek(int fd, off_t offset, int whence, int32_t *retval){
#if OPT_SHELLPROJECT
	struct openfile *file = NULL;
	struct lock *ftlock = curproc->p_lk;
	off_t new_offset;
	struct stat stats;
	int err = 0;

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
	// es. console e' una stream di caratteri, non ha una dimensione
	// quindi non è seekable (scorrevole)
	if (!VOP_ISSEEKABLE(file->vn)) {
		return ESPIPE; // not seekable
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
		err = VOP_STAT(file->vn, &stats); // ritorna 0 in caso di successo
			if (err) { // error
				lock_release(file->lk);
				return err;
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

"flags" specifies how to open the file. 
The optional mode argument provides the file permissions to use. only meaningful in Unix.
*/
int sys_open(userptr_t pathname, int flags, mode_t mode, int32_t *retval)
{
#if OPT_SHELLPROJECT
	struct openfile *file;
	struct vnode *vn;
	int err;
	struct lock *ftlock = curproc->p_lk;
	int fd;

	if (pathname==NULL){
		return EFAULT;
	}

	// copy the string from user space to kernel space 
	// necessary to avoid direct access to user memory
	char *kpath = (char *) kmalloc(PATH_MAX*sizeof(char));
	size_t actual_len;
	if (kpath==NULL){
		return ENOMEM;
	}

	err = copyinstr(pathname, kpath, PATH_MAX, &actual_len);
	if (err) {
		kfree(kpath);
		return err;
	}

	// ci serve il vnode, si occupa vfs_open di chiamare VOP_OPEN
	err = vfs_open(kpath, flags, mode, &vn);
	if (err) {
		kfree(kpath);
		return err;
	}
	// allochiamo struct openfile
	file = kmalloc(sizeof(struct openfile));
	if (file == NULL) {
		vfs_close(vn);
		kfree(kpath);
		return ENOMEM;
	}

	// init openfile fields
	file->vn = vn;
	file->offset = 0;
	file->mode = flags;
	file->ref_count = 1;
	
	// vfs_open might modify kpath (e.g. using strtok). To be safe, we can just use a generic lock name 
	// or kpath. Here we use a generic name since the path is no longer pristine.
	file->lk = lock_create("filelock");
	kfree(kpath); // we can safely free it now
	
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

/*
  Cambia la current working directory del processo corrente.
  Porta la stringa del path da user space a kernel space in modo sicuro
  Ritorna 0 in caso di successo, un codice errno altrimenti.
 */
int sys_chdir(const_userptr_t pathname)
{
#if OPT_SHELLPROJECT
	char *path;
	int result;

	if (pathname == NULL) {
		return EFAULT;
	}

	path = kmalloc(PATH_MAX);
	if (path == NULL) {
		return ENOMEM;
	}

	// copia sicura dallo user space
	result = copyinstr(pathname, path, PATH_MAX, NULL);
	if (result) {
		kfree(path);
		return result;
	}

	result = vfs_chdir(path);
	kfree(path);
	return result;
#endif
}

/*
  Scrive in buf il nome della cwd, al massimo buflen byte.
  Ritorna 0 e mette in *retval il numero di byte scritti, oppure un errno.
 */
int sys___getcwd(userptr_t buf, size_t buflen, int32_t *retval)
{
#if OPT_SHELLPROJECT
	struct iovec iov;
	struct uio userio;
	int result;

	// uio per trasferimento verso buffer utente
	iov.iov_ubase = buf;
	iov.iov_len = buflen;

	userio.uio_iov = &iov;
	userio.uio_iovcnt = 1;
	userio.uio_offset = 0;
	userio.uio_resid = buflen;
	userio.uio_segflg = UIO_USERSPACE;
	userio.uio_rw = UIO_READ;
	userio.uio_space = proc_getas();

	result = vfs_getcwd(&userio);
	if (result) {
		return result;
	}

	// byte scritti nel buffer utente
	*retval = buflen - userio.uio_resid;
	return 0;
#endif
}

#if OPT_SHELLPROJECT
/*
  release a reference to an openfile: drop ref_count and, when it reaches 0,
  actually close the vnode and free the structure.
 */
static void openfile_decref(struct openfile *file)
{
	lock_acquire(file->lk);
	file->ref_count--;

	if (file->ref_count > 0) {
		// still in use by someone else -> do nothing
		lock_release(file->lk);
	} else {
		// effectively close
		lock_release(file->lk);
		vfs_close(file->vn);
		lock_destroy(file->lk);
		kfree(file);
	}
}
#endif

int sys_close(int fd){
#if OPT_SHELLPROJECT
	struct openfile *file;
	struct lock *ftlock = curproc->p_lk;

	if (fd < 0 || fd >= OPEN_MAX) {
		return EBADF;
	}

	lock_acquire(ftlock);
	file = curproc->fileTable[fd];
	
	if (file == NULL) {
		lock_release(ftlock);
		return EBADF;
	}

	// remove from filetable
	curproc->fileTable[fd] = NULL;
	lock_release(ftlock);

	openfile_decref(file);
	return 0;
#endif
}

/*
  dup2(oldfd, newfd): fa in modo che newfd si riferisca allo stesso openfile
  di oldfd (stesso seek pointer). Se newfd era gia' aperto viene chiuso.
  Ritorna newfd in *retval.
 */
int sys_dup2(int oldfd, int newfd, int32_t *retval){
#if OPT_SHELLPROJECT
	struct openfile *file;
	struct openfile *to_close;
	struct lock *ftlock = curproc->p_lk;

	// entrambi gli fd devono stare nel range valido
	if (oldfd < 0 || oldfd >= OPEN_MAX ||
	    newfd < 0 || newfd >= OPEN_MAX) {
		return EBADF;
	}

	lock_acquire(ftlock);

	file = curproc->fileTable[oldfd];
	if (file == NULL) {
		lock_release(ftlock);
		return EBADF;
	}

	// dup2 di un fd su se stesso
	if (oldfd == newfd) {
		lock_release(ftlock);
		*retval = newfd;
		return 0;
	}

	to_close = curproc->fileTable[newfd];

	// oldfd e newfd condividono gia' lo stesso openfile
	if (file == to_close) {
		lock_release(ftlock);
		*retval = newfd;
		return 0;
	}

	// clona: aggiungo il riferimento PRIMA di installarlo in newfd, cosi'
	// newfd non e' mai visibile in uno stato "chiuso ma non riassegnato"
	lock_acquire(file->lk);
	file->ref_count++;
	lock_release(file->lk);

	curproc->fileTable[newfd] = file;

	lock_release(ftlock);

	// se newfd era aperto su un altro file, ora lo chiudo
	if (to_close != NULL) {
		openfile_decref(to_close);
	}

	*retval = newfd;
	return 0;
#endif
}

#ifndef _LINUX_ERRNO_H
#define _LINUX_ERRNO_H



#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

#define ATHW_EOK          0L
#define ATHW_ENULLP       300    /*! null ptr */
#define ATHW_ESZEROL      301    /// length of zero 
#define ATHW_ESLMIN       302    /// length is below min
#define ATHW_ESLMAX       303    /// length exceeds max 

#define ATHW_EPERM        1  /* Operation not permitted */
#define ATHW_ENOENT       2  /* No such file or directory */
#define ATHW_ESRCH        3  /* No such process */
#define ATHW_EINTR        4  /* Interrupted system call */
#define ATHW_EIO          5  /* I/O error */
#define ATHW_ENXIO        6  /* No such device or address */
#define ATHW_E2BIG        7  /* Argument list too long */
#define ATHW_ENOEXEC      8  /* Exec format error */
#define ATHW_EBADF        9  /* Bad file number */
#define ATHW_ECHILD      10  /* No child processes */
#define ATHW_EAGAIN      11  /* Try again */
#define ATHW_ENOMEM      12  /* Out of memory */
#define ATHW_EACCES      13  /* Permission denied */
#define ATHW_EFAULT      14  /* Bad address */
#define ATHW_ENOTBLK     15  /* Block device required */
#define ATHW_EBUSY       16  /* Device or resource busy */
#define ATHW_EEXIST      17  /* File exists */
#define ATHW_EXDEV       18  /* Cross-device link */
#define ATHW_ENODEV      19  /* No such device */
#define ATHW_ENOTDIR     20  /* Not a directory */
#define ATHW_EISDIR      21  /* Is a directory */
#define ATHW_EINVAL      22  /* Invalid argument */
#define ATHW_ENFILE      23  /* File table overflow */
#define ATHW_EMFILE      24  /* Too many open files */
#define ATHW_ENOTTY      25  /* Not a typewriter */
#define ATHW_ETXTBSY     26  /* Text file busy */
#define ATHW_EFBIG       27  /* File too large */
#define ATHW_ENOSPC      28  /* No space left on device */
#define ATHW_ESPIPE      29  /* Illegal seek */
#define ATHW_EROFS       30  /* Read-only file system */
#define ATHW_EMLINK      31  /* Too many links */
#define ATHW_EPIPE       32  /* Broken pipe */
#define ATHW_EDOM        33  /* Math argument out of domain of func */
#define ATHW_ERANGE      34  /* Math result not representable */

#define ATHW_EDEADLK     35  /* Resource deadlock would occur */
#define ATHW_ENAMETOOLONG    36  /* File name too long */
#define ATHW_ENOLCK      37  /* No record locks available */

#define ATHW_ENOSYS      38  /* Invalid system call number */

#define ATHW_ENOTEMPTY   39  /* Directory not empty */
#define ATHW_ELOOP       40  /* Too many symbolic links encountered */
#define ATHW_EWOULDBLOCK EAGAIN  /* Operation would block */
#define ATHW_ENOMSG      42  /* No message of desired type */
#define ATHW_EIDRM       43  /* Identifier removed */
#define ATHW_ECHRNG      44  /* Channel number out of range */
#define ATHW_EL2NSYNC    45  /* Level 2 not synchronized */
#define ATHW_EL3HLT      46  /* Level 3 halted */
#define ATHW_EL3RST      47  /* Level 3 reset */
#define ATHW_ELNRNG      48  /* Link number out of range */
#define ATHW_EUNATCH     49  /* Protocol driver not attached */
#define ATHW_ENOCSI      50  /* No CSI structure available */
#define ATHW_EL2HLT      51  /* Level 2 halted */
#define ATHW_EBADE       52  /* Invalid exchange */
#define ATHW_EBADR       53  /* Invalid request descriptor */
#define ATHW_EXFULL      54  /* Exchange full */
#define ATHW_ENOANO      55  /* No anode */
#define ATHW_EBADRQC     56  /* Invalid request code */
#define ATHW_EBADSLT     57  /* Invalid slot */

#define ATHW_EDEADLOCK   EDEADLK

#define ATHW_EBFONT      59  /* Bad font file format */
#define ATHW_ENOSTR      60  /* Device not a stream */
#define ATHW_ENODATA     61  /* No data available */
#define ATHW_ETIME       62  /* Timer expired */
#define ATHW_ENOSR       63  /* Out of streams resources */
#define ATHW_ENONET      64  /* Machine is not on the network */
#define ATHW_ENOPKG      65  /* Package not installed */
#define ATHW_EREMOTE     66  /* Object is remote */
#define ATHW_ENOLINK     67  /* Link has been severed */
#define ATHW_EADV        68  /* Advertise error */
#define ATHW_ESRMNT      69  /* Srmount error */
#define ATHW_ECOMM       70  /* Communication error on send */
#define ATHW_EPROTO      71  /* Protocol error */
#define ATHW_EMULTIHOP   72  /* Multihop attempted */
#define ATHW_EDOTDOT     73  /* RFS specific error */
#define ATHW_EBADMSG     74  /* Not a data message */
#define ATHW_EOVERFLOW   75  /* Value too large for defined data type */
#define ATHW_ENOTUNIQ    76  /* Name not unique on network */
#define ATHW_EBADFD      77  /* File descriptor in bad state */
#define ATHW_EREMCHG     78  /* Remote address changed */
#define ATHW_ELIBACC     79  /* Can not access a needed shared library */
#define ATHW_ELIBBAD     80  /* Accessing a corrupted shared library */
#define ATHW_ELIBSCN     81  /* .lib section in a.out corrupted */
#define ATHW_ELIBMAX     82  /* Attempting to link in too many shared libraries */
#define ATHW_ELIBEXEC    83  /* Cannot exec a shared library directly */
#define ATHW_EILSEQ      84  /* Illegal byte sequence */
#define ATHW_ERESTART    85  /* Interrupted system call should be restarted */
#define ATHW_ESTRPIPE    86  /* Streams pipe error */
#define ATHW_EUSERS      87  /* Too many users */
#define ATHW_ENOTSOCK    88  /* Socket operation on non-socket */
#define ATHW_EDESTADDRREQ    89  /* Destination address required */
#define ATHW_EMSGSIZE    90  /* Message too long */
#define ATHW_EPROTOTYPE  91  /* Protocol wrong type for socket */
#define ATHW_ENOPROTOOPT 92  /* Protocol not available */
#define ATHW_EPROTONOSUPPORT 93  /* Protocol not supported */
#define ATHW_ESOCKTNOSUPPORT 94  /* Socket type not supported */
#define ATHW_EOPNOTSUPP  95  /* Operation not supported on transport endpoint */
#define ATHW_EPFNOSUPPORT    96  /* Protocol family not supported */
#define ATHW_EAFNOSUPPORT    97  /* Address family not supported by protocol */
#define ATHW_EADDRINUSE  98  /* Address already in use */
#define ATHW_EADDRNOTAVAIL   99  /* Cannot assign requested address */
#define ATHW_ENETDOWN    100 /* Network is down */
#define ATHW_ENETUNREACH 101 /* Network is unreachable */
#define ATHW_ENETRESET   102 /* Network dropped connection because of reset */
#define ATHW_ECONNABORTED    103 /* Software caused connection abort */
#define ATHW_ECONNRESET  104 /* Connection reset by peer */
#define ATHW_ENOBUFS     105 /* No buffer space available */
#define ATHW_EISCONN     106 /* Transport endpoint is already connected */
#define ATHW_ENOTCONN    107 /* Transport endpoint is not connected */
#define ATHW_ESHUTDOWN   108 /* Cannot send after transport endpoint shutdown */
#define ATHW_ETOOMANYREFS    109 /* Too many references: cannot splice */
#define ATHW_ETIMEDOUT   110 /* Connection timed out */
#define ATHW_ECONNREFUSED    111 /* Connection refused */
#define ATHW_EHOSTDOWN   112 /* Host is down */
#define ATHW_EHOSTUNREACH    113 /* No route to host */
#define ATHW_EALREADY    114 /* Operation already in progress */
#define ATHW_EINPROGRESS 115 /* Operation now in progress */
#define ATHW_ESTALE      116 /* Stale file handle */
#define ATHW_EUCLEAN     117 /* Structure needs cleaning */
#define ATHW_ENOTNAM     118 /* Not a XENIX named type file */
#define ATHW_ENAVAIL     119 /* No XENIX semaphores available */
#define ATHW_EISNAM      120 /* Is a named type file */
#define ATHW_EREMOTEIO   121 /* Remote I/O error */
#define ATHW_EDQUOT      122 /* Quota exceeded */

#define ATHW_ENOMEDIUM   123 /* No medium found */
#define ATHW_EMEDIUMTYPE 124 /* Wrong medium type */
#define ATHW_ECANCELED   125 /* Operation Canceled */
#define ATHW_ENOKEY      126 /* Required key not available */
#define ATHW_EKEYEXPIRED 127 /* Key has expired */
#define ATHW_EKEYREVOKED 128 /* Key has been revoked */
#define ATHW_EKEYREJECTED    129 /* Key was rejected by service */

/* for robust mutexes */
#define ATHW_EOWNERDEAD  130 /* Owner died */
#define ATHW_ENOTRECOVERABLE 131 /* State not recoverable */

#define ATHW_ERFKILL     132 /* Operation not possible due to RF-kill */

#define ATHW_EHWPOISON   133 /* Memory page has hardware error */

#define ATHW_ERESTARTSYS 512
#define ATHW_ERESTARTNOINTR  513
#define ATHW_ERESTARTNOHAND  514 /* restart if no handler.. */
#define ATHW_ENOIOCTLCMD 515 /* No ioctl command */
#define ATHW_ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */
#define ATHW_EPROBE_DEFER    517 /* Driver requests probe retry */
#define ATHW_EOPENSTALE  518 /* open found a stale dentry */

/* Defined for the NFSv3 protocol */
#define ATHW_EBADHANDLE  521 /* Illegal NFS file handle */
#define ATHW_ENOTSYNC    522 /* Update synchronization mismatch */
#define ATHW_EBADCOOKIE  523 /* Cookie is stale */
#define ATHW_ENOTSUPP    524 /* Operation is not supported */
#define ATHW_ETOOSMALL   525 /* Buffer or request is too small */
#define ATHW_ESERVERFAULT    526 /* An untranslatable error occurred */
#define ATHW_EBADTYPE    527 /* Type not supported by server */
#define ATHW_EJUKEBOX    528 /* Request initiated, but will not complete before timeout */
#define ATHW_EIOCBQUEUED 529 /* iocb queued, will get completion event */
#define ATHW_ERECALLCONFLICT 530 /* conflict with recalled state */

#ifdef __cplusplus
}
#endif
#endif

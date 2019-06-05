//only define FILE in enclave (application's stdio.h should have this typedef already)


#if defined(SGX_ENCLAVE) && !defined(SGX_LIB_STDIO_H)
#define SGX_LIB_STDIO_H



struct _iobuf {
        char *_ptr;
        int   _cnt;
        char *_base;
        int   _flag;
        int   _file;
        int   _charbuf;
        int   _bufsiz;
        char *_tmpfname;
        };
typedef struct _iobuf FILE;


 typedef unsigned long clockid_t;


typedef struct timezone *__restrict __timezone_ptr_t;
typedef unsigned long int __ino_t;
typedef __ino_t ino_t;
typedef unsigned int __uid_t;
typedef __uid_t uid_t;
typedef unsigned int gid_t;
typedef unsigned int __gid_t;
typedef unsigned int __mode_t;
typedef __mode_t mode_t;
typedef unsigned long int __dev_t;
typedef __dev_t dev_t;
typedef long int __off_t;
typedef int __pid_t;
typedef __pid_t pid_t;
typedef unsigned long int __syscall_ulong_t;
typedef long int __syscall_slong_t;
typedef long unsigned int size_t;
typedef long int ssize_t;
typedef long int __blksize_t;
typedef long int __blkcnt_t;
typedef unsigned long int __nlink_t;
typedef long int __suseconds_t;
typedef long int __time_t;
typedef __time_t time_t;



  struct timeval {
      long tv_sec;
      long tv_usec;
   };
 
   struct timezone {
      int tz_minuteswest;
      int tz_dsttime;
   };

struct timespec {
	time_t	tv_sec;		/* seconds */
	long	tv_nsec;	/* and nanoseconds */
};
typedef __clock_t clock_t;

#define CLOCKS_PER_SEC  ((__clock_t) 1000000)

#define SEEK_CUR    1
#define SEEK_END    2
#define SEEK_SET    0
#define FILENAME_MAX    260
#define FOPEN_MAX       20
#define _SYS_OPEN       20
#define TMP_MAX         32767  /* SHRT_MAX */

#endif
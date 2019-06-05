#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"


#ifndef _BYPASS_TO_SGXSSL_
#define _BYPASS_TO_SGXSSL_

//file flags
#define O_RDONLY	0x0000
#define O_WRONLY	0x0001
#define O_RDWR		0x0002
#define O_ACCMODE	0x0003
#define O_CREAT		0x0100	/* second byte, away from DOS bits */
#define O_EXCL		0x0200
#define O_NOCTTY	0x0400
#define O_TRUNC		0x0800
#define O_APPEND	0x1000
#define O_NONBLOCK	0x2000



/*
 * The IDs of the various system clocks (for POSIX.1b interval timers):
 */
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME			7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9
/*
 * The driver implementing this got removed. The clock ID is kept as a
 * place holder. Do not reuse!
 */
#define CLOCK_SGI_CYCLE			10
#define CLOCK_TAI			11

#define MAX_CLOCKS			16
#define CLOCKS_MASK			(CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO			CLOCK_MONOTONIC

/*
 * The various flags for setting POSIX.1b interval timers:
 */
#define TIMER_ABSTIME			0x01

// ocalls wrapper
//#define mmap sgxssl_mmap



#if defined(__cplusplus)
extern "C" {
#endif

#define stdin SGX_STDIN
#define stdout SGX_STDOUT 
#define stderr SGX_STDERR

#define WRAPBUFSIZ 15000

int printf(const char* fmt, ...);
FILE* fopen(const char* filename, const char* mode);
int fclose(FILE* stream) ;
int fprintf(int FILESTREAM, const char* fmt, ...);
int fscanf(FILE *stream, const char *fmt, ...);
void rewind(FILE* file) ;
long sgx_rand(void);
int gettimeofday(void * tv, void * tz);
#if defined(__cplusplus)
}
#endif

#endif

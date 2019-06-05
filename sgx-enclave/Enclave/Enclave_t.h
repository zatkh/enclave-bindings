#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "../ocall_types.h"
#include "../sgx_lib_stdio.h"
#include "time.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void test_ecall(void);
void test_main(void);
void ecall_main(int argc, char** argv);

sgx_status_t SGX_CDECL get_raws(int* retval, const char* path);
sgx_status_t SGX_CDECL ocall_println_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_error(const char* str);
sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t length);
sgx_status_t SGX_CDECL ocall_getcwd(char** retval, char* buf, size_t size);
sgx_status_t SGX_CDECL ocall_getpid(int* retval);
sgx_status_t SGX_CDECL ocall_getuid(int* retval);
sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name);
sgx_status_t SGX_CDECL ocall_open64(int* retval, const char* filename, int flags, mode_t mode);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_lseek64(off_t* retval, int fd, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_read(int* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write(int* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_fcntl(int* retval, int fd, int cmd, void* arg, size_t size);
sgx_status_t SGX_CDECL ocall_unlink(int* retval, const char* pathname);
sgx_status_t SGX_CDECL fopen_ocall(FILE** retval, const char* filename, const char* mode);
sgx_status_t SGX_CDECL fclose_ocall(int* retval, FILE* stream);
sgx_status_t SGX_CDECL ocall_fprintf(FILE* stream, const char* format);
sgx_status_t SGX_CDECL ocall_fscanf(FILE* stream, const char* format);
sgx_status_t SGX_CDECL rewind_ocall(FILE* file);
sgx_status_t SGX_CDECL ocall_lns(int* retval, FILE* file);
sgx_status_t SGX_CDECL ocall_readln(char** retval, FILE* file);
sgx_status_t SGX_CDECL ocall_fprint_string(int* retval, SGX_WRAPPER_FILE stream, const char* s);
sgx_status_t SGX_CDECL ocall_clock(clock_t* retval);
sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* t);
sgx_status_t SGX_CDECL ocall_gettimeofday(int* retval, void* tv, int tv_size, void* tz, int tz_size);
sgx_status_t SGX_CDECL ocall_gettimeofday2(int* retval, void* tv, int tv_size);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

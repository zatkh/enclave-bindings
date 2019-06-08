#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "../ocall_types.h"
#include "../sgx_lib_stdio.h"
#include "time.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef GET_RAWS_DEFINED__
#define GET_RAWS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, get_raws, (const char* path));
#endif
#ifndef OCALL_PRINTLN_STRING_DEFINED__
#define OCALL_PRINTLN_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_println_string, (const char* str));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_PRINT_ERROR_DEFINED__
#define OCALL_PRINT_ERROR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_error, (const char* str));
#endif
#ifndef OCALL_FTRUNCATE_DEFINED__
#define OCALL_FTRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate, (int fd, off_t length));
#endif
#ifndef OCALL_GETCWD_DEFINED__
#define OCALL_GETCWD_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getcwd, (char* buf, size_t size));
#endif
#ifndef OCALL_GETPID_DEFINED__
#define OCALL_GETPID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpid, (void));
#endif
#ifndef OCALL_GETUID_DEFINED__
#define OCALL_GETUID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getuid, (void));
#endif
#ifndef OCALL_GETENV_DEFINED__
#define OCALL_GETENV_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getenv, (const char* name));
#endif
#ifndef OCALL_OPEN64_DEFINED__
#define OCALL_OPEN64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open64, (const char* filename, int flags, mode_t mode));
#endif
#ifndef OCALL_CLOSE_DEFINED__
#define OCALL_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
#endif
#ifndef OCALL_LSEEK64_DEFINED__
#define OCALL_LSEEK64_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek64, (int fd, off_t offset, int whence));
#endif
#ifndef OCALL_READ_DEFINED__
#define OCALL_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int fd, void* buf, size_t count));
#endif
#ifndef OCALL_WRITE_DEFINED__
#define OCALL_WRITE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int fd, const void* buf, size_t count));
#endif
#ifndef OCALL_FSYNC_DEFINED__
#define OCALL_FSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int fd));
#endif
#ifndef OCALL_FCNTL_DEFINED__
#define OCALL_FCNTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl, (int fd, int cmd, void* arg, size_t size));
#endif
#ifndef OCALL_UNLINK_DEFINED__
#define OCALL_UNLINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unlink, (const char* pathname));
#endif
#ifndef FOPEN_OCALL_DEFINED__
#define FOPEN_OCALL_DEFINED__
FILE* SGX_UBRIDGE(SGX_NOCONVENTION, fopen_ocall, (const char* filename, const char* mode));
#endif
#ifndef FCLOSE_OCALL_DEFINED__
#define FCLOSE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, fclose_ocall, (FILE* stream));
#endif
#ifndef OCALL_FPRINTF_DEFINED__
#define OCALL_FPRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fprintf, (FILE* stream, const char* format));
#endif
#ifndef OCALL_FSCANF_DEFINED__
#define OCALL_FSCANF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fscanf, (FILE* stream, const char* format));
#endif
#ifndef REWIND_OCALL_DEFINED__
#define REWIND_OCALL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, rewind_ocall, (FILE* file));
#endif
#ifndef OCALL_LNS_DEFINED__
#define OCALL_LNS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lns, (FILE* file));
#endif
#ifndef OCALL_READLN_DEFINED__
#define OCALL_READLN_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readln, (FILE* file));
#endif
#ifndef OCALL_FPRINT_STRING_DEFINED__
#define OCALL_FPRINT_STRING_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fprint_string, (SGX_WRAPPER_FILE stream, const char* s));
#endif
#ifndef OCALL_CLOCK_DEFINED__
#define OCALL_CLOCK_DEFINED__
clock_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clock, (void));
#endif
#ifndef OCALL_TIME_DEFINED__
#define OCALL_TIME_DEFINED__
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_time, (time_t* t));
#endif
#ifndef OCALL_GETTIMEOFDAY_DEFINED__
#define OCALL_GETTIMEOFDAY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettimeofday, (void* tv, int tv_size, void* tz, int tz_size));
#endif
#ifndef OCALL_GETTIMEOFDAY2_DEFINED__
#define OCALL_GETTIMEOFDAY2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettimeofday2, (void* tv, int tv_size));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef CREATE_SESSION_OCALL_DEFINED__
#define CREATE_SESSION_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
#endif
#ifndef EXCHANGE_REPORT_OCALL_DEFINED__
#define EXCHANGE_REPORT_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
#endif
#ifndef CLOSE_SESSION_OCALL_DEFINED__
#define CLOSE_SESSION_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
#endif
#ifndef INVOKE_SERVICE_OCALL_DEFINED__
#define INVOKE_SERVICE_OCALL_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
#endif

sgx_status_t test_ecall(sgx_enclave_id_t eid);
sgx_status_t test_main(sgx_enclave_id_t eid);
sgx_status_t ecall_main(sgx_enclave_id_t eid, int argc, char** argv);
sgx_status_t ecall_nacl_main(sgx_enclave_id_t eid, int* retval, int argc, char** argv);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

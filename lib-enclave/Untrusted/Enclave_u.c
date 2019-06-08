#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_main_t {
	int ms_argc;
	char** ms_argv;
} ms_ecall_main_t;

typedef struct ms_ecall_nacl_main_t {
	int ms_retval;
	int ms_argc;
	char** ms_argv;
} ms_ecall_nacl_main_t;

typedef struct ms_get_raws_t {
	int ms_retval;
	const char* ms_path;
} ms_get_raws_t;

typedef struct ms_ocall_println_string_t {
	const char* ms_str;
} ms_ocall_println_string_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_print_error_t {
	const char* ms_str;
} ms_ocall_print_error_t;

typedef struct ms_ocall_ftruncate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_length;
} ms_ocall_ftruncate_t;

typedef struct ms_ocall_getcwd_t {
	char* ms_retval;
	int ocall_errno;
	char* ms_buf;
	size_t ms_size;
} ms_ocall_getcwd_t;

typedef struct ms_ocall_getpid_t {
	int ms_retval;
} ms_ocall_getpid_t;

typedef struct ms_ocall_getuid_t {
	int ms_retval;
} ms_ocall_getuid_t;

typedef struct ms_ocall_getenv_t {
	char* ms_retval;
	const char* ms_name;
} ms_ocall_getenv_t;

typedef struct ms_ocall_open64_t {
	int ms_retval;
	const char* ms_filename;
	int ms_flags;
	mode_t ms_mode;
} ms_ocall_open64_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_lseek64_t {
	off_t ms_retval;
	int ocall_errno;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_lseek64_t;

typedef struct ms_ocall_read_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
} ms_ocall_write_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fsync_t;

typedef struct ms_ocall_fcntl_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_cmd;
	void* ms_arg;
	size_t ms_size;
} ms_ocall_fcntl_t;

typedef struct ms_ocall_unlink_t {
	int ms_retval;
	const char* ms_pathname;
} ms_ocall_unlink_t;

typedef struct ms_fopen_ocall_t {
	FILE* ms_retval;
	const char* ms_filename;
	const char* ms_mode;
} ms_fopen_ocall_t;

typedef struct ms_fclose_ocall_t {
	int ms_retval;
	FILE* ms_stream;
} ms_fclose_ocall_t;

typedef struct ms_ocall_fprintf_t {
	FILE* ms_stream;
	const char* ms_format;
} ms_ocall_fprintf_t;

typedef struct ms_ocall_fscanf_t {
	FILE* ms_stream;
	const char* ms_format;
} ms_ocall_fscanf_t;

typedef struct ms_rewind_ocall_t {
	FILE* ms_file;
} ms_rewind_ocall_t;

typedef struct ms_ocall_lns_t {
	int ms_retval;
	FILE* ms_file;
} ms_ocall_lns_t;

typedef struct ms_ocall_readln_t {
	char* ms_retval;
	int ocall_errno;
	FILE* ms_file;
} ms_ocall_readln_t;

typedef struct ms_ocall_fprint_string_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_stream;
	const char* ms_s;
} ms_ocall_fprint_string_t;

typedef struct ms_ocall_clock_t {
	clock_t ms_retval;
} ms_ocall_clock_t;

typedef struct ms_ocall_time_t {
	time_t ms_retval;
	time_t* ms_t;
} ms_ocall_time_t;

typedef struct ms_ocall_gettimeofday_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
	void* ms_tz;
	int ms_tz_size;
} ms_ocall_gettimeofday_t;

typedef struct ms_ocall_gettimeofday2_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
} ms_ocall_gettimeofday2_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

static sgx_status_t SGX_CDECL Enclave_get_raws(void* pms)
{
	ms_get_raws_t* ms = SGX_CAST(ms_get_raws_t*, pms);
	ms->ms_retval = get_raws(ms->ms_path);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_println_string(void* pms)
{
	ms_ocall_println_string_t* ms = SGX_CAST(ms_ocall_println_string_t*, pms);
	ocall_println_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_error(void* pms)
{
	ms_ocall_print_error_t* ms = SGX_CAST(ms_ocall_print_error_t*, pms);
	ocall_print_error(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ftruncate(void* pms)
{
	ms_ocall_ftruncate_t* ms = SGX_CAST(ms_ocall_ftruncate_t*, pms);
	ms->ms_retval = ocall_ftruncate(ms->ms_fd, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getcwd(void* pms)
{
	ms_ocall_getcwd_t* ms = SGX_CAST(ms_ocall_getcwd_t*, pms);
	ms->ms_retval = ocall_getcwd(ms->ms_buf, ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getpid(void* pms)
{
	ms_ocall_getpid_t* ms = SGX_CAST(ms_ocall_getpid_t*, pms);
	ms->ms_retval = ocall_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getuid(void* pms)
{
	ms_ocall_getuid_t* ms = SGX_CAST(ms_ocall_getuid_t*, pms);
	ms->ms_retval = ocall_getuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getenv(void* pms)
{
	ms_ocall_getenv_t* ms = SGX_CAST(ms_ocall_getenv_t*, pms);
	ms->ms_retval = ocall_getenv(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open64(void* pms)
{
	ms_ocall_open64_t* ms = SGX_CAST(ms_ocall_open64_t*, pms);
	ms->ms_retval = ocall_open64(ms->ms_filename, ms->ms_flags, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lseek64(void* pms)
{
	ms_ocall_lseek64_t* ms = SGX_CAST(ms_ocall_lseek64_t*, pms);
	ms->ms_retval = ocall_lseek64(ms->ms_fd, ms->ms_offset, ms->ms_whence);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_fd, ms->ms_buf, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_fd, ms->ms_buf, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl(void* pms)
{
	ms_ocall_fcntl_t* ms = SGX_CAST(ms_ocall_fcntl_t*, pms);
	ms->ms_retval = ocall_fcntl(ms->ms_fd, ms->ms_cmd, ms->ms_arg, ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_unlink(void* pms)
{
	ms_ocall_unlink_t* ms = SGX_CAST(ms_ocall_unlink_t*, pms);
	ms->ms_retval = ocall_unlink(ms->ms_pathname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_fopen_ocall(void* pms)
{
	ms_fopen_ocall_t* ms = SGX_CAST(ms_fopen_ocall_t*, pms);
	ms->ms_retval = fopen_ocall(ms->ms_filename, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_fclose_ocall(void* pms)
{
	ms_fclose_ocall_t* ms = SGX_CAST(ms_fclose_ocall_t*, pms);
	ms->ms_retval = fclose_ocall(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fprintf(void* pms)
{
	ms_ocall_fprintf_t* ms = SGX_CAST(ms_ocall_fprintf_t*, pms);
	ocall_fprintf(ms->ms_stream, ms->ms_format);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fscanf(void* pms)
{
	ms_ocall_fscanf_t* ms = SGX_CAST(ms_ocall_fscanf_t*, pms);
	ocall_fscanf(ms->ms_stream, ms->ms_format);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_rewind_ocall(void* pms)
{
	ms_rewind_ocall_t* ms = SGX_CAST(ms_rewind_ocall_t*, pms);
	rewind_ocall(ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lns(void* pms)
{
	ms_ocall_lns_t* ms = SGX_CAST(ms_ocall_lns_t*, pms);
	ms->ms_retval = ocall_lns(ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readln(void* pms)
{
	ms_ocall_readln_t* ms = SGX_CAST(ms_ocall_readln_t*, pms);
	ms->ms_retval = ocall_readln(ms->ms_file);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fprint_string(void* pms)
{
	ms_ocall_fprint_string_t* ms = SGX_CAST(ms_ocall_fprint_string_t*, pms);
	ms->ms_retval = ocall_fprint_string(ms->ms_stream, ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_clock(void* pms)
{
	ms_ocall_clock_t* ms = SGX_CAST(ms_ocall_clock_t*, pms);
	ms->ms_retval = ocall_clock();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_time(void* pms)
{
	ms_ocall_time_t* ms = SGX_CAST(ms_ocall_time_t*, pms);
	ms->ms_retval = ocall_time(ms->ms_t);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gettimeofday(void* pms)
{
	ms_ocall_gettimeofday_t* ms = SGX_CAST(ms_ocall_gettimeofday_t*, pms);
	ms->ms_retval = ocall_gettimeofday(ms->ms_tv, ms->ms_tv_size, ms->ms_tz, ms->ms_tz_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gettimeofday2(void* pms)
{
	ms_ocall_gettimeofday2_t* ms = SGX_CAST(ms_ocall_gettimeofday2_t*, pms);
	ms->ms_retval = ocall_gettimeofday2(ms->ms_tv, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[38];
} ocall_table_Enclave = {
	38,
	{
		(void*)Enclave_get_raws,
		(void*)Enclave_ocall_println_string,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_print_error,
		(void*)Enclave_ocall_ftruncate,
		(void*)Enclave_ocall_getcwd,
		(void*)Enclave_ocall_getpid,
		(void*)Enclave_ocall_getuid,
		(void*)Enclave_ocall_getenv,
		(void*)Enclave_ocall_open64,
		(void*)Enclave_ocall_close,
		(void*)Enclave_ocall_lseek64,
		(void*)Enclave_ocall_read,
		(void*)Enclave_ocall_write,
		(void*)Enclave_ocall_fsync,
		(void*)Enclave_ocall_fcntl,
		(void*)Enclave_ocall_unlink,
		(void*)Enclave_fopen_ocall,
		(void*)Enclave_fclose_ocall,
		(void*)Enclave_ocall_fprintf,
		(void*)Enclave_ocall_fscanf,
		(void*)Enclave_rewind_ocall,
		(void*)Enclave_ocall_lns,
		(void*)Enclave_ocall_readln,
		(void*)Enclave_ocall_fprint_string,
		(void*)Enclave_ocall_clock,
		(void*)Enclave_ocall_time,
		(void*)Enclave_ocall_gettimeofday,
		(void*)Enclave_ocall_gettimeofday2,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_create_session_ocall,
		(void*)Enclave_exchange_report_ocall,
		(void*)Enclave_close_session_ocall,
		(void*)Enclave_invoke_service_ocall,
	}
};
sgx_status_t test_ecall(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t test_main(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_main(sgx_enclave_id_t eid, int argc, char** argv)
{
	sgx_status_t status;
	ms_ecall_main_t ms;
	ms.ms_argc = argc;
	ms.ms_argv = argv;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_nacl_main(sgx_enclave_id_t eid, int* retval, int argc, char** argv)
{
	sgx_status_t status;
	ms_ecall_nacl_main_t ms;
	ms.ms_argc = argc;
	ms.ms_argv = argv;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


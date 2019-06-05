#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdarg.h> // for variable arguments functions
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_trts.h"



// At this point we have already definitions needed for  ocall interface, so:
#define DO_NOT_REDEFINE_FOR_OCALL
#include "Enclave_t.h"

// For open64 need to define this
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)

long int sysconf(int name){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

int open64(const char *filename, int flags, ...){
    mode_t mode = 0; // file permission bitmask

    // Get the mode_t from arguments
	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list valist;
		va_start(valist, flags);
		mode = va_arg(valist, mode_t);
		va_end(valist);
	}

    int ret;
    sgx_status_t status = ocall_open64(&ret, filename, flags, mode);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

off_t lseek64(int fd, off_t offset, int whence){
    off_t ret;
    sgx_status_t status = ocall_lseek64(&ret, fd, offset, whence);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

unsigned int sleep(unsigned int seconds){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

void *dlopen(const char *filename, int flag){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
}

char *dlerror(void){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

void *dlsym(void *handle, const char *symbol){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);

}

int dlclose(void *handle){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

int utimes(const char *filename, const struct timeval times[2]){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

struct tm *localtime(const time_t *timep){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

pid_t getpid(void){
    int ret;
    sgx_status_t status = ocall_getpid(&ret);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

int fsync(int fd){
    int ret;
    sgx_status_t status = ocall_fsync(&ret, fd);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}


int close(int fd){
    int ret;
    sgx_status_t status = ocall_close(&ret, fd);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

int access(const char *pathname, int mode){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

char *getcwd(char *buf, size_t size){
    char* ret;
    sgx_status_t status = ocall_getcwd(&ret, buf, size);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}


int sgx_ftruncate(int fd, off_t length){
    int ret;
    sgx_status_t status = ocall_ftruncate(&ret, fd, length);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

int fcntl(int fd, int cmd, ... /* arg */ ){
    // Read one argument
    va_list valist;
	va_start(valist, cmd);
	void* arg = va_arg(valist, void*);
	va_end(valist);

    int ret;
    sgx_status_t status = ocall_fcntl(&ret, fd, cmd, arg, sizeof(void*));
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

ssize_t read(int fd, void *buf, size_t count){
    int ret;
    sgx_status_t status = ocall_read(&ret, fd, buf, count);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return (ssize_t)ret;
}

ssize_t write(int fd, const void *buf, size_t count){
    int ret;
    sgx_status_t status = ocall_write(&ret, fd, buf, count);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return (ssize_t)ret;
}

int fchmod(int fd, mode_t mode){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

int unlink(const char *pathname){
    int ret;
    sgx_status_t status = ocall_unlink(&ret, pathname);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

int mkdir(const char *pathname, mode_t mode) {
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

int rmdir(const char *pathname){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

int fchown(int fd, uid_t owner, gid_t group){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

uid_t geteuid(void){
    int ret;
    sgx_status_t status = ocall_getuid(&ret);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return (uid_t)ret;
}

char* getenv(const char *name){
    char* ret = NULL;
    sgx_status_t status = ocall_getenv(&ret, name);
    if (status != SGX_SUCCESS) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_", __func__);
        ocall_print_error(error_msg);
    }
    return ret;
}

void *mmap64(void *addr, size_t len, int prot, int flags, int fildes, off_t off){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
}

int munmap(void *addr, size_t length){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_print_error(error_msg);
    return 0;
}


FILE* fopen(const char* filename, const char* mode) 
{
  FILE* ret;
  fopen_ocall(&ret, filename, mode);
  return ret;
}

int fclose(FILE* stream) {
  int ret;
  fclose_ocall(&ret, stream);
  return ret;
}




void rewind(FILE* file) 
{
  rewind_ocall(file);
}

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int sgx_rand(void)
{
	int retv;
	sgx_read_rand((unsigned char*)&retv, sizeof(retv));
	return retv;
}




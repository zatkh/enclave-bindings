// This is a real implementation of ocalls
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h> 
#include <sys/time.h>
#include "Enclave_u.h"

#define MAX_FILE_BUFFER 65000

FILE* fd_tables[MAX_FILE_BUFFER];

int ocall_ftruncate(int fd, off_t length){
    //printf("Entering %s\n", __func__);
    return ftruncate(fd, length);
}

char* ocall_getcwd(char *buf, size_t size){
    //printf("Entering %s\n", __func__);
    return getcwd(buf, size);
}

int ocall_getpid(void){
    //printf("Entering %s\n", __func__);
    return getpid();
}

int ocall_open64(const char *filename, int flags, mode_t mode){
    //printf("Entering %s\n", __func__);
    return open(filename, flags, mode); // redirect it to open() instead of open64()
}

off_t ocall_lseek64(int fd, off_t offset, int whence){
    //printf("Entering %s\n", __func__);
    return lseek(fd, offset, whence); // redirect it to lseek() instead of lseek64()
}

int ocall_read(int fd, void *buf, size_t count){
    //printf("Entering %s\n", __func__);
    return read(fd, buf, count);
}

int ocall_write(int fd, const void *buf, size_t count){
    //printf("Entering %s\n", __func__);
    return write(fd, buf, count);
}

int ocall_fcntl(int fd, int cmd, void* arg, size_t size){
    //printf("Entering %s\n", __func__);
    return fcntl(fd, cmd, arg);
}

int ocall_close(int fd){
    //printf("Entering %s\n", __func__);
    return close(fd);
}

int ocall_unlink(const char *pathname){
    //printf("Entering %s\n", __func__);
    return unlink(pathname);
}

int ocall_getuid(void){
    //printf("Entering %s\n", __func__);
    return getuid();
}

char* ocall_getenv(const char *name){
    //printf("Entering %s\n", __func__);
    return getenv(name);
}

int ocall_fsync(int fd){
    //printf("Entering %s\n", __func__);
    return fsync(fd);
}

FILE* fopen_ocall(const char* filename, const char* mode) {
  return fopen(filename, mode);
}


int fclose_ocall(FILE* stream) {
  return fclose(stream);
}

void ocall_fprintf(FILE* stream,const char *format)
{
    fprintf(stream,"%s",format);

}

void ocall_fscanf(FILE* stream,const char *format)
{
    fscanf(stream,"%s",format);

}

void rewind_ocall(FILE* file) {
  rewind(file);
}



// New 2D array of floats.
static float** new2d(const int rows, const int cols)
{
    float** row = (float**) malloc((rows) * sizeof(float*));
    for(int r = 0; r < rows; r++)
        row[r] = (float*) malloc((cols) * sizeof(float));
    return row;
}

static int lns(FILE* const file)
{
    int ch = EOF;
    int lines = 0;
    int pc = '\n';
    while((ch = getc(file)) != EOF)
    {
        if(ch == '\n')
            lines++;
        pc = ch;
    }
    if(pc != '\n')
        lines++;
    rewind(file);
    return lines;
}


// Reads a line from a file.
static char* readln(FILE* const file)
{
    int ch = EOF;
    int reads = 0;
    int size = 128;
    char* line = (char*) malloc((size) * sizeof(char));
    while((ch = getc(file)) != '\n' && ch != EOF)
    {
        line[reads++] = ch;
        if(reads + 1 == size)
            line = (char*) realloc((line), (size *= 2) * sizeof(char));
    }
    line[reads] = '\0';
    return line;
}

// Reads a line from a file.
char* ocall_readln(FILE* file)
{
    int ch = EOF;
    int reads = 0;
    int size = 128;
    char* line = (char*) malloc((size) * sizeof(char));
    while((ch = getc(file)) != '\n' && ch != EOF)
    {
        line[reads++] = ch;
        if(reads + 1 == size)
            line = (char*) realloc((line), (size *= 2) * sizeof(char));
    }
    line[reads] = '\0';

    return line;
}


 int ocall_lns(FILE* file)
{
    int ch = EOF;
    int lines = 0;
    int pc = '\n';
    while((ch = getc(file)) != EOF)
    {
        if(ch == '\n')
            lines++;
        pc = ch;
    }
    if(pc != '\n')
        lines++;
    rewind(file);
    return lines;
}

int get_raws(const char* path)
{
     FILE* file = fopen(path, "r");
    if(file == NULL)
    {
        printf("Could not open %s\n", path);
        printf("Get it from the machine learning database: ");
        printf("wget http://archive.ics.uci.edu/ml/machine-learning-databases/semeion/semeion.data\n");
        exit(1);
    }
    const int rows= lns(file);
    return rows;

}


time_t ocall_time(time_t *t)  
{
    return time(t);
}

int ocall_gettimeofday(void *tv_cast, int tv_size, void *tz_cast, int tz_size)	
{
	struct timeval *tv = (struct timeval*)tv_cast;
	struct timezone *tz = (struct timezone*)tz_cast;
	return gettimeofday(tv, tz);
}


int ocall_gettimeofday2(void *tv_cast, int tv_size)	
{
	struct timeval tv; // (struct timeval*)tv_cast;
	int ret = gettimeofday(&tv, NULL);
	memcpy(tv_cast, &tv, sizeof(struct timeval));
	return ret;
}


int ocall_clock_gettime(struct timespec *tp)
{
    int ret=clock_gettime(CLOCK_REALTIME, tp); 
    return ret;


}

clock_t ocall_clock(void)
{
    return  clock();
}


FILE* getFile(int fd)   
{
    if (fd == SGX_STDIN)
        return stdin;

    if (fd == SGX_STDOUT)
        return stdout;

    if (fd == SGX_STDERR)
        return stderr;

    if (fd<=0)
        return NULL;

    return fd_tables[fd];
}

int ocall_fprint_string(SGX_WRAPPER_FILE FILESTREAM, const char* s)   {
    FILE* file = NULL;
    file = getFile(FILESTREAM);    
    return fprintf(file, "%s", s);
}

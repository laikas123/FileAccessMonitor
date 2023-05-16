#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "hello.h"
#include "hello.skel.h"
#include <dirent.h> 
#include <fcntl.h>


const char word[16] = "pseudocat";
const char word2[16] = "read";
const char word3[16] = "cat";

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	if(strstr(m->command, word3) == NULL){
		return;
	}

	if (strstr(m->message, word2) != NULL ) {
	
	

	// if(m -> pid == 11091){
		printf("%lu  %lu  %s\n", m->pid, m->fd, m->command);
	// }
	char path_str[100];
    sprintf(path_str, "/proc/%d/fd", m->pid);
	// printf("path str is %s \n", path_str);

	DIR *mydir;
    struct dirent *myfile;
    struct stat mystat;

	// printf("msg is %s \n", m->message);
	

    char buf[512];
    mydir = opendir(path_str);
	if(mydir != NULL){
		
	
		while((myfile = readdir(mydir)) != NULL)
		{
			// printf("HERE 1 \n");

			sprintf(buf, "%s/%s", path_str, myfile->d_name);
			stat(buf, &mystat);
			// printf("%zu\n",mystat.st_size);
			// printf("%zu\n", mystat.st_ino);
			// printf(" %s\n", myfile->d_name);

			if(mystat.st_ino == 1396301 || mystat.st_ino == 1319264 || mystat.st_ino == 5768513 || mystat.st_ino == 1318781){
				printf("WAIT STOP!\n");
				printf("inode = %d \n", mystat.st_ino);
				printf("%lu  %lu  %s\n", m->pid, m->fd, m->command);
			}else{
				// printf("inode = %d \n", mystat.st_ino);
			}


		}
	}
    if(mydir != NULL){
		// printf("HERE 2 \n");
    	closedir(mydir);
	}

	

	}
    //    printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
	

	// printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);


	
}


void handle_event_openat(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct openat_dat_t *m = data;

	// printf("%lu  %lu %d %s\n", m->pid, m->uid, m->dirfd, m->filename);

	
}

void handle_event_exit_read(void *ctx, void *data, unsigned int data_sz)
{
	struct exit_read_dat_t *m = data;

	if(strstr(m->command, word3) == NULL){
		return;
	}

	printf("exit_read START%lu  %lu %d \n", m->pid, m->uid,  m->bytes_read);

	
	
	char path_str[100];
    sprintf(path_str, "/proc/%d/fd", m->pid);

	DIR *mydir;
    struct dirent *myfile;
    struct stat mystat;

    char buf[512];
    mydir = opendir(path_str);
	if(mydir != NULL){
		
	
		while((myfile = readdir(mydir)) != NULL)
		{
			// printf("HERE 1 \n");

			sprintf(buf, "%s/%s", path_str, myfile->d_name);
			stat(buf, &mystat);
			// printf("%zu\n",mystat.st_size);
			printf("%zu\n", mystat.st_ino);
			printf(" %s\n", myfile->d_name);
			

			if(mystat.st_ino == 1396301 || mystat.st_ino == 1319264 || mystat.st_ino == 5768513 || mystat.st_ino == 1318781){
				printf("WAIT STOP!\n");
				printf("inode = %d \n", mystat.st_ino);
				
			}


		}
	}
    if(mydir != NULL){
    	closedir(mydir);
	}

	printf("exit_read STOP%lu  %lu %d \n", m->pid, m->uid,  m->bytes_read);
}


void handle_event_exit_openat(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct exit_openat_dat_t *m = data;

	if(strstr(m->command, word3) == NULL){
		return;
	}	

	printf("exit_open START%lu  %lu %d \n", m->pid, m->uid,  m->fd);

	
	
	char path_str[100];
    sprintf(path_str, "/proc/%d/fd", m->pid);
	printf("path string is %s\n", path_str);

	DIR *mydir;
    struct dirent *myfile;
    struct stat mystat;

    char buf[512];
    mydir = opendir(path_str);
	if(mydir != NULL){
		
	
		while((myfile = readdir(mydir)) != NULL)
		{
			// printf("HERE 1 \n");

			sprintf(buf, "%s/%s", path_str, myfile->d_name);
			stat(buf, &mystat);
			// printf("%zu\n",mystat.st_size);
			printf("%zu\n", mystat.st_ino);
			printf(" %s\n", myfile->d_name);
			

			if(mystat.st_ino == 1396301 || mystat.st_ino == 1319264 || mystat.st_ino == 5768513 || mystat.st_ino == 1318781){
				printf("WAIT STOP!\n");
				printf("inode = %d \n", mystat.st_ino);
				
			}


		}
	}
    if(mydir != NULL){
    	closedir(mydir);
	}

	printf("exit_open STOP%lu  %lu %d \n", m->pid, m->uid,  m->fd);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	// printf("lost event\n");
}

int main()
{
    struct hello_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct perf_buffer *pb = NULL;
	struct perf_buffer *pb_openat = NULL;
	struct perf_buffer *pb_exit_openat = NULL;
	struct perf_buffer *pb_exit_read = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	skel = hello_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = hello_bpf__load(skel);
	// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}
	
	if (err) {
		printf("Failed to load BPF object\n");
		hello_bpf__destroy(skel);
		return 1;
	}

	// Attach the progams to the events
	err = hello_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hello_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	pb_openat = perf_buffer__new(bpf_map__fd(skel->maps.output_openat), 8, handle_event_openat, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer pb_read\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	pb_exit_openat = perf_buffer__new(bpf_map__fd(skel->maps.output_exit_openat), 8, handle_event_exit_openat, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer pb_read\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	pb_exit_read = ring_buffer__new(bpf_map__fd(skel->maps.output_exit_read), handle_event_exit_read, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer pb_read\n");
		hello_bpf__destroy(skel);
        return 1;
	}


//this could probably be threaded....
	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		err = perf_buffer__poll(pb_openat, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		err = perf_buffer__poll(pb_exit_openat, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		err = ring_buffer__poll(pb_exit_read, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	hello_bpf__destroy(skel);
	return -err;
}

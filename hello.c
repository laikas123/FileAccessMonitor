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
#include <time.h>

int x = 0;

void timestamp()
{
    time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */
    printf("%s",asctime( localtime(&ltime) ) );
}


const char word[16] = "pseudocat";
const char word2[16] = "read";
const char word3[16] = "cat";

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event_read(void *ctx, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	if(strstr(m->command, word3) == NULL){
		return;
	}

	printf("enter_read START%lu  %lu %s\n", m->pid, m->uid, m->command);
	x += 1;
	printf("X= %d\n", x);

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
	printf("enter_read STOP%lu  %lu  %s \n", m->pid, m->uid, m->command);
	x += 1;
	printf("X= %d\n", x);

	
}


void handle_event_openat(void *ctx, void *data, unsigned int data_sz)
{
	struct openat_dat_t *m = data;

	// printf("%lu  %lu %d %s\n", m->pid, m->uid, m->dirfd, m->filename);

	
}

void handle_event_close(void *ctx, void *data, unsigned int data_sz)
{
	struct close_dat_t *m = data;

	if(strstr(m->command, word3) == NULL){
		return;
	}

	printf("enter_close START%lu  %lu %s \n", m->pid, m->uid, m->command);
	x += 1;
	printf("X= %d\n", x);
	// printf("%lu  %lu %d %s\n", m->pid, m->uid, m->dirfd, m->filename);

	
}

void handle_event_exit_read(void *ctx, void *data, unsigned int data_sz)
{
	struct exit_read_dat_t *m = data;

	if(strstr(m->command, word3) == NULL){
		return;
	}

	printf("exit_read START%lu  %lu  %s \n", m->pid, m->uid,  m->command);
	x += 1;
	printf("X= %d\n", x);
	
	
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
			// printf("%zu\n", mystat.st_ino);
			// printf(" %s\n", myfile->d_name);
			

			if(mystat.st_ino == 1396301 || mystat.st_ino == 1319264 || mystat.st_ino == 5768513 || mystat.st_ino == 1318781){
				printf("WAIT STOP!\n");timestamp();
				printf("inode = %d \n", mystat.st_ino);
				
			}


		}
	}
    if(mydir != NULL){
    	closedir(mydir);
	}

	printf("exit_read STOP%lu  %lu  %s\n", m->pid, m->uid,   m->command);
	x += 1;
	printf("X= %d\n", x);
}


void handle_event_exit_openat(void *ctx, void *data, unsigned int data_sz)
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
			// printf("%zu\n", mystat.st_ino);
			// printf(" %s\n", myfile->d_name);
			

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
	struct ring_buffer *rb = NULL;
	struct ring_buffer *rb_openat = NULL;
	struct ring_buffer *rb_exit_openat = NULL;
	struct ring_buffer *rb_exit_read = NULL;
	struct ring_buffer *rb_close = NULL;

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

	rb = ring_buffer__new(bpf_map__fd(skel->maps.output), handle_event_read, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	rb_openat = ring_buffer__new(bpf_map__fd(skel->maps.output_openat), handle_event_openat, NULL, NULL);
	if (!rb_openat) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer rb_read\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	rb_exit_openat = ring_buffer__new(bpf_map__fd(skel->maps.output_exit_openat), handle_event_exit_openat, NULL, NULL);
	if (!rb_exit_openat) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer rb_read\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	rb_exit_read = ring_buffer__new(bpf_map__fd(skel->maps.output_exit_read), handle_event_exit_read, NULL, NULL);
	if (!rb_exit_read) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer rb_read\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	rb_close = ring_buffer__new(bpf_map__fd(skel->maps.output_close), handle_event_close, NULL, NULL);
	if (!rb_close) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer rb_read\n");
		hello_bpf__destroy(skel);
        return 1;
	}


//this could probably be threaded....
	while (true) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: 123 %d\n", err);
			// break;
		}
		// err = ring_buffer__poll(rb_openat, 100 /* timeout, ms */);
		// // Ctrl-C gives -EINTR
		// if (err == -EINTR) {
		// 	err = 0;
		// 	break;
		// }
		// if (err < 0) {
		// 	printf("Error polling ring buffer:456 %d\n", err);
		// 	break;
		// }
		err = ring_buffer__poll(rb_exit_openat, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer:789 %d\n", err);
			break;
		}
		err = ring_buffer__poll(rb_exit_read, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer:101112 %d\n", err);
			break;
		}
		err = ring_buffer__poll(rb_close, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer:131415 %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	hello_bpf__destroy(skel);
	return -err;
}

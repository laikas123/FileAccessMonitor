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
#include <stdint.h> 


#define SEC_TO_NS(sec) ((sec)*1000000000)


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

int handle_event_read(void *ctx, void *data, size_t data_sz)
{
	struct read_data_t *kern_dat = data;

	//only log for specific list of files to monitor
	if(kern_dat-> inode != 1396301 && kern_dat -> inode != 1318781){
		return 0;
	}

	FILE* outfile;
  
    // open file for writing
    outfile = fopen("/home/logan/read_access.log", "a+");
    if (outfile == NULL) {
        fprintf(stderr, "\nError opened file\n");
        exit(1);
    }

	uint64_t nanoseconds;
    struct timespec ts;
    int return_code = timespec_get(&ts, TIME_UTC);
    if (return_code == 0)
    {
        printf("Failed to obtain timestamp.\n");
        nanoseconds = UINT64_MAX; // use this to indicate error
    }
    else
    {
        // `ts` now contains your timestamp in seconds and nanoseconds! To 
        // convert the whole struct to nanoseconds, do this:
        nanoseconds = SEC_TO_NS((uint64_t)ts.tv_sec) + (uint64_t)ts.tv_nsec;
    }
  
    // int chars_written = fprintf(outfile, "%d %d %d %lu %s\n", kern_dat->pid, kern_dat -> uid, kern_dat -> fd, kern_dat -> inode, kern_dat -> command);
	int chars_written = fprintf(outfile, "{\"timestamp\":%llu,\"pid\":%d,\"uid\":%d,\"fd\":%d,\"inode\":%lu,\"command\":\"%s\"}\n", nanoseconds, kern_dat->pid, kern_dat -> uid, kern_dat -> fd, kern_dat -> inode, kern_dat -> command);
  


	if(chars_written < 0){
		printf("Error writing to file, err = %d", chars_written);
	}else{
		printf("Wrote %d chars to file", chars_written);
	}

    // close file
    fclose(outfile);

	return 0;
	
}


int main()
{
    struct hello_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct ring_buffer *rb_read = NULL;

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

	rb_read = ring_buffer__new(bpf_map__fd(skel->maps.output_read), handle_event_read, NULL, NULL);
	if (!rb_read) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	


//this could probably be threaded....
	while (true) {
		err = ring_buffer__poll(rb_read, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		// if (err < 0) {
			// printf("Error polling ring buffer, timeout: %d\n", err);
			// break;
		// }
		
	}

	ring_buffer__free(rb_read);
	hello_bpf__destroy(skel);
	return -err;
}

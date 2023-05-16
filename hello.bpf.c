#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello.h"

const char kprobe_sys_msg[16] = "sys_execve";
const char kprobe_msg[16] = "do_execve";
const char fentry_msg[16] = "fentry_execve";
const char tp_msg[16] = "tp_execve";
const char tp_msg2[16] = "tp_openat";
const char tp_msg3[16] = "pseudocat";
const char tp_msg4[16] = "read";
const char tp_btf_exec_msg[16] = "tp_btf_exec";
const char raw_tp_exec_msg[16] = "raw_tp_exec";
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output_openat SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output_exit_openat SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} output_exit_read SEC(".maps");

// name: sys_enter_execve
// ID: 622
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * filename;    offset:16;      size:8; signed:0;
//         field:const char *const * argv; offset:24;      size:8; signed:0;
//         field:const char *const * envp; offset:32;      size:8; signed:0;
struct my_syscalls_enter_execve {
	unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

	long syscall_nr;
	void *filename_ptr;
	long argv_ptr;
	long envp_ptr;
};

// SEC("tp/syscalls/sys_enter_execve")
// int tp_sys_enter_execve(struct my_syscalls_enter_execve *ctx) {
//    struct data_t data = {}; 

//    bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg);
//    bpf_printk("%s: ctx->filename_ptr: %s", tp_msg, ctx->filename_ptr);

//    data.pid = bpf_get_current_pid_tgid() >> 32;
//    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

//    bpf_get_current_comm(&data.command, sizeof(data.command));
//    bpf_probe_read_user(&data.path, sizeof(data.path), ctx->filename_ptr);  

//    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
//    return 0;
// }

struct my_syscalls_enter_openat {
    unsigned short common_type;	
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long __syscall_nr;
	long dfd;
	long filename_ptr;
	long flags;
	umode_t mode;
};


SEC("tp/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct my_syscalls_enter_openat *ctx) {
   struct openat_dat_t data = {}; 

   
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.dirfd = ctx->dfd;

   bpf_probe_read_user(&data.filename, sizeof(data.filename), ctx->filename_ptr);  
   if(data.uid == 1000){
        bpf_perf_event_output(ctx, &output_openat, BPF_F_CURRENT_CPU, &data, sizeof(data));   
   }
   return 0;
}


struct my_syscalls_exit_openat {
    unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long __syscall_nr;
	long ret;

};


SEC("tp/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct my_syscalls_exit_openat *ctx) {
   struct exit_openat_dat_t data = {}; 

 


   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.fd = ctx-> ret;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   if(data.uid == 1000){
    bpf_perf_event_output(ctx, &output_exit_openat, BPF_F_CURRENT_CPU, &data, sizeof(data));   
   }
   return 0;
}

// struct my_syscalls_enter_read {
// 	unsigned short common_type;
// 	unsigned char common_flags;
// 	unsigned char common_preempt_count;
// 	long common_pid;
// 	unsigned long __syscall_nr;
// 	unsigned long fd;	
// 	unsigned long buf;
// 	unsigned long count;
// };

struct my_syscalls_enter_read {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long buf;
	long count;
};


SEC("tp/syscalls/sys_enter_read")
int tp_sys_enter_read(struct my_syscalls_enter_read *ctx) {
   struct data_t data = {}; 

   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg4);


   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.fd = ctx -> fd;

   bpf_get_current_comm(&data.command, sizeof(data.command));
//    bpf_probe_read_user(&data.path, sizeof(data.path), ctx->oldname);
//    bpf_probe_read_user(&data.path2, sizeof(data.path2), ctx->newname);  
   
   int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   if(uid == 1000){
        bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
   }
   return 0;
}


struct my_syscalls_exit_read {
    unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long __syscall_nr;
	long ret;

};


SEC("tp/syscalls/sys_exit_read")
int tp_sys_exit_read(struct my_syscalls_exit_read *ctx) {
   struct exit_read_dat_t data = {}; 

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.bytes_read = ctx-> ret;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   if(data.uid == 1000){
    bpf_ringbuf_output(&output_exit_read, &data, sizeof(data), 0);   
   }
   return 0;
}



// struct my_syscalls_enter_symlinkat {
//     unsigned short common_type;
// 	unsigned char common_flags;
// 	unsigned char common_preempt_count;
// 	int common_pid;

// 	long __syscall_nr;
// 	long oldname;
// 	long newdfd;
// 	long newname;
// };

// SEC("tp/syscalls/sys_enter_symlinkat")
// int tp_sys_enter_symlinkat(struct my_syscalls_enter_symlinkat *ctx) {
//    struct data_t data = {}; 

//    bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg4);
// //    bpf_printk("%s: ctx->filename_ptr: %s", tp_msg2, ctx->filename_ptr);
// //    bpf_printk("%s: ctx->filename_ptr: %s", tp_msg2, ctx->dfd);


//    data.pid = bpf_get_current_pid_tgid() >> 32;
//    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

//    bpf_get_current_comm(&data.command, sizeof(data.command));
//    bpf_probe_read_user(&data.path, sizeof(data.path), ctx->oldname);
//    bpf_probe_read_user(&data.path2, sizeof(data.path2), ctx->newname);  

//    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
//    return 0;
// }

// struct my_syscalls_enter_symlink {
//     unsigned short common_type;	
// 	unsigned char common_flags;
// 	unsigned char common_preempt_count;
// 	long common_pid;
//     long __syscall_nr;
// 	long oldname;
// 	long newname;

// };


// SEC("tp_btf/sys_enter_symlink")
// int handle_exec(struct trace_event_raw_sys_enter_symlink *ctx){
//    struct data_t data = {}; 

//    bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg4);
// //    bpf_printk("%s: ctx->filename_ptr: %s", tp_msg2, ctx->filename_ptr);
// //    bpf_printk("%s: ctx->filename_ptr: %s", tp_msg2, ctx->dfd);


//    data.pid = bpf_get_current_pid_tgid() >> 32;
//    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

//    bpf_get_current_comm(&data.command, sizeof(data.command));
//    bpf_probe_read_user(&data.path, sizeof(data.path), ctx->oldname);
//    bpf_probe_read_user(&data.path2, sizeof(data.path2), ctx->newname);  

//    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
//    return 0;
// }
// SEC("tp/syscalls/sys_enter_symlink")
// int tp_sys_enter_symlink(struct my_syscalls_enter_symlink *ctx) {
//    struct data_t data = {}; 

//    bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg4);
// //    bpf_printk("%s: ctx->filename_ptr: %s", tp_msg2, ctx->filename_ptr);
// //    bpf_printk("%s: ctx->filename_ptr: %s", tp_msg2, ctx->dfd);


//    data.pid = bpf_get_current_pid_tgid() >> 32;
//    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

//    bpf_get_current_comm(&data.command, sizeof(data.command));
//    bpf_probe_read_user(&data.path, sizeof(data.path), ctx->oldname);
//    bpf_probe_read_user(&data.path2, sizeof(data.path2), ctx->newname);  

//    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
//    return 0;
// }


char LICENSE[] SEC("license") = "Dual BSD/GPL";

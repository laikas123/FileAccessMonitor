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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_openat SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_exit_openat SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_exit_read SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_close SEC(".maps");

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

//    bpf_ringbuf_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
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
        bpf_ringbuf_output(&output_openat, &data, sizeof(data), 0);   
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
    bpf_ringbuf_output(&output_exit_openat, &data, sizeof(data), 0);   
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

//    struct task_struct *t = (struct task_struct *)bpf_get_current_task();

//    struct task_struct *task = (void *)bpf_get_current_task();


   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.fd = ctx -> fd;

   bpf_get_current_comm(&data.command, sizeof(data.command));
//    bpf_probe_read_user(&data.path, sizeof(data.path), ctx->oldname);
//    bpf_probe_read_user(&data.path2, sizeof(data.path2), ctx->newname);  
   
   int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if(uid == 1000){
        struct task_struct *task = (void *)bpf_get_current_task();
        
        int testpid;

        


        bpf_probe_read(&testpid, sizeof(testpid), (void *)&task->pid); 

        bpf_printk("PID ++++ = %d and =%d", testpid, data.pid); 




        // struct files_struct *files;

        struct file my_file;

        struct inode *f_inode;

        long unsigned int i_ino;

        // if(task->files->fd_array != NULL && index < sizeof(task -> files -> fd_array)){
        // bpf_probe_read(&files, sizeof(files), (void *)&task->files);

        // bpf_probe_read(&my_file, sizeof(my_file), (void *)&(*files->fd_array[2]) );

        // // bpf_probe_read(&my_file, sizeof(my_file), (void *)&fd_array[0]);

        // bpf_probe_read(&f_inode, sizeof(f_inode), (void *)&my_file.f_inode);

        // bpf_probe_read(&i_ino, sizeof(i_ino), (void *)&f_inode -> i_ino);


        // u64 inode = task->mm->exe_file->f_inode->i_ino;

        // struct mm_struct *mm;


        // u64 inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);

        struct file **fd = BPF_CORE_READ(task, files, fdt, fd);

        struct file* files[5];

        bpf_probe_read(&files[0], sizeof(files[0]), &fd[0]);
        bpf_probe_read(&files[1], sizeof(files[1]), &fd[1]);
        bpf_probe_read(&files[2], sizeof(files[2]), &fd[2]);
        bpf_probe_read(&files[3], sizeof(files[3]), &fd[3]);
        bpf_probe_read(&files[4], sizeof(files[4]), &fd[4]);

        struct inode* inodes[4];

        bpf_probe_read(&inodes[0], sizeof(inodes[0]), &files[0]->f_inode);
        bpf_probe_read(&inodes[1], sizeof(inodes[1]), &files[1]->f_inode);
        bpf_probe_read(&inodes[2], sizeof(inodes[2]), &files[2]->f_inode);
        bpf_probe_read(&inodes[3], sizeof(inodes[3]), &files[3]->f_inode);
        bpf_probe_read(&inodes[4], sizeof(inodes[4]), &files[4]->f_inode);

        u64 inos[4];
        bpf_probe_read(&inos[0], sizeof(inos[0]), &inodes[0]->i_ino);
        bpf_probe_read(&inos[1], sizeof(inos[1]), &inodes[1]->i_ino);
        bpf_probe_read(&inos[2], sizeof(inos[2]), &inodes[2]->i_ino);
        bpf_probe_read(&inos[3], sizeof(inos[3]), &inodes[3]->i_ino);
        bpf_probe_read(&inos[4], sizeof(inos[4]), &inodes[4]->i_ino);

        bpf_printk("fd ++++++= %d", ctx->fd);
        bpf_printk("inode +++++= %lu ", inos[0]);
        bpf_printk("inode +++++= %lu ", inos[1]);
        bpf_printk("inode +++++= %lu ", inos[2]);
        bpf_printk("inode +++++= %lu ", inos[3]);
        bpf_printk("inode +++++= %lu ", inos[4]);


        

        // bpf_printk("inode +++++= %lu ", inode);

        // }
        // if(0 < sizeof(task->files->fd_array)){
        //     bpf_probe_read(&i_ino, sizeof(i_ino), (void *)&task->files->fd_array[0]->f_inode->i_ino);
        // }
        // bpf_probe_read(&i_ino, sizeof(i_ino), (void *)&task->files->fd_array[0]->f_inode->i_ino); 

        // int count;

        // for(int i = 0; i < 6; i++){
        //     bpf_printk("index % d inode = %d of pid = %d", i, f_str -> fd_array[i]->f_inode, testpid); 
        // }


          
        
   }


   if(uid == 1000){
        bpf_ringbuf_output(&output, &data, sizeof(data), 0);   
   }
   return 0;
}

// int hello_execve(void *ctx) {
//     bpf_trace_printk("Executing a program");
//     return 0;
// }


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



struct my_syscalls_enter_close {
    unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long __syscall_nr;
	long fd;

};


SEC("tp/syscalls/sys_enter_close")
int tp_sys_enter_close(struct my_syscalls_enter_close *ctx) {
   struct close_dat_t data = {}; 

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.fd = ctx-> fd;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   if(data.uid == 1000){
    bpf_ringbuf_output(&output_close, &data, sizeof(data), 0);   
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

//    bpf_ringbuf_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
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

//    bpf_ringbuf_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
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

//    bpf_ringbuf_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
//    return 0;
// }


char LICENSE[] SEC("license") = "Dual BSD/GPL";

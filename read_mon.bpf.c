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
} output_read SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");




struct my_syscalls_enter_read {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long buf;
	long count;
};


SEC("tp/syscalls/sys_enter_read")
int tp_sys_enter_read(struct my_syscalls_enter_read *ctx) {
    
    //struct to hold logged data
    struct read_data_t data = {}; 

    //log the pid, uid, fd, and the command
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.fd = ctx -> fd;
    bpf_get_current_comm(&data.command, sizeof(data.command));


    //get the task struct for the process that enetered read
    struct task_struct *task = (void *)bpf_get_current_task();

    //this is the files array, the fd is the index into this
    //and let's you get the file struct for the fd
    struct file **fdtable = BPF_CORE_READ(task, files, fdt, fd);

    //file struct for fd
    struct file* file;
    //inode struct for fd
    struct inode* inode;
    //inode number for fd
    u64 ino;


    //print the fd and inode 
    bpf_probe_read(&file, sizeof(file), &fdtable[data.fd]);
    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);
    bpf_probe_read(&ino, sizeof(ino), &inode->i_ino);
    bpf_printk("fd ++++++= %d", ctx->fd);
    bpf_printk("inode +++++= %lu ", ino);


    //log the inode
    data.inode = ino;
        

    //send data to buffer to be polled by userspace
    bpf_ringbuf_output(&output_read, &data, sizeof(data), 0);   

    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";

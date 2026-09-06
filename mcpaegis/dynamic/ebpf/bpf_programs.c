#include <uapi/linux/ptrace.h>
#include <uapi/linux/fcntl.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <bcc/proto.h>

#ifndef TARGET_CGROUP_ID
#define TARGET_CGROUP_ID 0
#endif

#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif

enum event_kind {
    KIND_FILE_OPEN = 1,
    KIND_FILE_READ = 2,
    KIND_FILE_WRITE = 3,
    KIND_FILE_UNLINK = 4,
    KIND_NET_CONNECT = 5,
    KIND_PROC_EXEC = 6,
    KIND_PROC_FORK = 7,
    KIND_DNS_RESPONSE = 8,
};

struct event_t {
    u64 timestamp;
    u64 cgroup_id;
    u32 pid;
    u32 ppid;
    u32 kind;
    u32 fd;
    u32 dest_ip;
    u32 dest_port;
    u32 child_pid;
    char comm[TASK_COMM_LEN];
    char path[256];
};

BPF_PERF_OUTPUT(events);

static __always_inline int fill_common(struct event_t *e) {
    u64 cg = bpf_get_current_cgroup_id();
    if (cg != (u64)TARGET_CGROUP_ID) {
        return 1;
    }
    e->cgroup_id = cg;
    e->timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task && task->real_parent) {
        e->ppid = task->real_parent->tgid;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return 0;
}

/*
 * Syscall arguments from pt_regs. BCC's syscall__* kprobes attach to
 * sys_openat / __x64_sys_openat and miss ARM64 (openat2, execveat, and
 * SYSCALL_WRAPPER symbols). raw_tracepoint/sys_enter sees every nr.
 */
static __always_inline unsigned long syscall_arg(struct pt_regs *regs, unsigned int idx) {
    unsigned long arg = 0;
#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
    switch (idx) {
    case 0:
        bpf_probe_read_kernel(&arg, sizeof(arg), &regs->di);
        break;
    case 1:
        bpf_probe_read_kernel(&arg, sizeof(arg), &regs->si);
        break;
    case 2:
        bpf_probe_read_kernel(&arg, sizeof(arg), &regs->dx);
        break;
    case 3:
        bpf_probe_read_kernel(&arg, sizeof(arg), &regs->r10);
        break;
    case 4:
        bpf_probe_read_kernel(&arg, sizeof(arg), &regs->r8);
        break;
    case 5:
        bpf_probe_read_kernel(&arg, sizeof(arg), &regs->r9);
        break;
    }
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
    if (idx < 6) {
        bpf_probe_read_kernel(&arg, sizeof(arg), &regs->regs[idx]);
    }
#endif
    return arg;
}

static __always_inline int submit_path(void *ctx, u32 kind, const char __user *filename, u32 extra) {
    struct event_t e = {};
    if (fill_common(&e)) {
        return 0;
    }
    e.kind = kind;
    e.fd = extra;
    if (filename) {
        bpf_probe_read_user_str(&e.path, sizeof(e.path), (void *)filename);
    }
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* One attach, no debugfs format files (TRACEPOINT_PROBE needs those). */
RAW_TRACEPOINT_PROBE(sys_enter) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    u64 nr = ctx->args[1];

#ifdef __NR_openat
    if (nr == __NR_openat) {
        const char __user *filename = (const char __user *)syscall_arg(regs, 1);
        int flags = (int)syscall_arg(regs, 2);
        u32 kind = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))
            ? KIND_FILE_WRITE
            : KIND_FILE_OPEN;
        return submit_path(ctx, kind, filename, (u32)flags);
    }
#endif
#ifdef __NR_openat2
    if (nr == __NR_openat2) {
        const char __user *filename = (const char __user *)syscall_arg(regs, 1);
        return submit_path(ctx, KIND_FILE_OPEN, filename, 0);
    }
#endif
#ifdef __NR_open
    if (nr == __NR_open) {
        const char __user *filename = (const char __user *)syscall_arg(regs, 0);
        int flags = (int)syscall_arg(regs, 1);
        u32 kind = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))
            ? KIND_FILE_WRITE
            : KIND_FILE_OPEN;
        return submit_path(ctx, kind, filename, (u32)flags);
    }
#endif
#ifdef __NR_unlinkat
    if (nr == __NR_unlinkat) {
        const char __user *pathname = (const char __user *)syscall_arg(regs, 1);
        return submit_path(ctx, KIND_FILE_UNLINK, pathname, 0);
    }
#endif
#ifdef __NR_execve
    if (nr == __NR_execve) {
        const char __user *filename = (const char __user *)syscall_arg(regs, 0);
        return submit_path(ctx, KIND_PROC_EXEC, filename, 0);
    }
#endif
#ifdef __NR_execveat
    if (nr == __NR_execveat) {
        const char __user *filename = (const char __user *)syscall_arg(regs, 1);
        return submit_path(ctx, KIND_PROC_EXEC, filename, 0);
    }
#endif
#ifdef __NR_connect
    if (nr == __NR_connect) {
        struct event_t e = {};
        if (fill_common(&e)) {
            return 0;
        }
        e.kind = KIND_NET_CONNECT;
        e.fd = (u32)syscall_arg(regs, 0);
        struct sockaddr *uservaddr = (struct sockaddr *)syscall_arg(regs, 1);
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);
        if (family == AF_INET) {
            struct sockaddr_in in = {};
            bpf_probe_read_user(&in, sizeof(in), uservaddr);
            e.dest_ip = in.sin_addr.s_addr;
            e.dest_port = ntohs(in.sin_port);
        }
        events.perf_submit(ctx, &e, sizeof(e));
        return 0;
    }
#endif
    return 0;
}

int kretprobe__kernel_clone(struct pt_regs *ctx) {
    struct event_t e = {};
    if (fill_common(&e)) {
        return 0;
    }
    e.kind = KIND_PROC_FORK;
    e.child_pid = (u32)PT_REGS_RC(ctx);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

static __always_inline int dns_from_sock(struct sock *sk, void *ctx) {
    if (!sk) {
        return 0;
    }
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    if (sport != 53 && dport != 53) {
        return 0;
    }
    struct event_t e = {};
    if (fill_common(&e)) {
        return 0;
    }
    e.kind = KIND_DNS_RESPONSE;
    e.dest_ip = sk->__sk_common.skc_daddr;
    e.dest_port = dport ? dport : sport;
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    return dns_from_sock(sk, ctx);
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    return dns_from_sock(sk, ctx);
}

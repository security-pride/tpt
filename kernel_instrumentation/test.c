// arch/arm64/kernel/test.c
#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/compat.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/test.h>
#include <linux/thread_info.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>

#include <asm/ptrace.h>
#include <asm/uaccess.h>

#define NR_compat_syscalls 387 /* 386 is error */

#define NR_compat_restart_syscall 0
#define NR_compat_exit 1
#define NR_compat_fork 2
#define NR_compat_read 3
#define NR_compat_write 4
#define NR_compat_open 5
#define NR_compat_close 6
#define NR_compat_creat 8
#define NR_compat_link 9
#define NR_compat_unlink 10
#define NR_compat_execve 11
#define NR_compat_chdir 12
#define NR_compat_mknod 14
#define NR_compat_chmod 15
#define NR_compat_lchown 16
#define NR_compat_lseek 19
#define NR_compat_getpid 20
#define NR_compat_mount 21
#define NR_compat_setuid 23
#define NR_compat_getuid 24
#define NR_compat_ptrace 26
#define NR_compat_pause 29
#define NR_compat_access 33
#define NR_compat_nice 34
#define NR_compat_sync 36
#define NR_compat_kill 37
#define NR_compat_rename 38
#define NR_compat_mkdir 39
#define NR_compat_rmdir 40
#define NR_compat_dup 41
#define NR_compat_pipe 42
#define NR_compat_times 43
#define NR_compat_brk 45
#define NR_compat_setgid 46
#define NR_compat_getgid 47
#define NR_compat_geteuid 49
#define NR_compat_getegid 50
#define NR_compat_acct 51
#define NR_compat_umount2 52
#define NR_compat_ioctl 54
#define NR_compat_fcntl 55
#define NR_compat_setpgid 57
#define NR_compat_umask 60
#define NR_compat_chroot 61
#define NR_compat_ustat 62
#define NR_compat_dup2 63
#define NR_compat_getppid 64
#define NR_compat_getpgrp 65
#define NR_compat_setsid 66
#define NR_compat_sigaction 67
#define NR_compat_setreuid 70
#define NR_compat_setregid 71
#define NR_compat_sigsuspend 72
#define NR_compat_sigpending 73
#define NR_compat_sethostname 74
#define NR_compat_setrlimit 75
#define NR_compat_getrusage 77
#define NR_compat_gettimeofday 78
#define NR_compat_settimeofday 79
#define NR_compat_getgroups 80
#define NR_compat_setgroups 81
#define NR_compat_symlink 83
#define NR_compat_readlink 85
#define NR_compat_uselib 86
#define NR_compat_swapon 87
#define NR_compat_reboot 88
#define NR_compat_munmap 91
#define NR_compat_truncate 92
#define NR_compat_ftruncate 93
#define NR_compat_fchmod 94
#define NR_compat_fchown 95
#define NR_compat_getpriority 96
#define NR_compat_setpriority 97
#define NR_compat_statfs 99
#define NR_compat_fstatfs 100
#define NR_compat_syslog 103
#define NR_compat_setitimer 104
#define NR_compat_getitimer 105
#define NR_compat_stat 106
#define NR_compat_lstat 107
#define NR_compat_fstat 108
#define NR_compat_vhangup 111
#define NR_compat_wait4 114
#define NR_compat_swapoff 115
#define NR_compat_sysinfo 116
#define NR_compat_fsync 118
#define NR_compat_sigreturn 119
#define NR_compat_clone 120
#define NR_compat_setdomainname 121
#define NR_compat_uname 122
#define NR_compat_adjtimex 124
#define NR_compat_mprotect 125
#define NR_compat_sigprocmask 126
#define NR_compat_init_module 128
#define NR_compat_delete_module 129
#define NR_compat_quotactl 131
#define NR_compat_getpgid 132
#define NR_compat_fchdir 133
#define NR_compat_bdflush 134
#define NR_compat_sysfs 135
#define NR_compat_personality 136
#define NR_compat_setfsuid 138
#define NR_compat_setfsgid 139
#define NR_compat__llseek 140
#define NR_compat_getdents 141
#define NR_compat__newselect 142
#define NR_compat_flock 143
#define NR_compat_msync 144
#define NR_compat_readv 145
#define NR_compat_writev 146
#define NR_compat_getsid 147
#define NR_compat_fdatasync 148
#define NR_compat__sysctl 149
#define NR_compat_mlock 150
#define NR_compat_munlock 151
#define NR_compat_mlockall 152
#define NR_compat_munlockall 153
#define NR_compat_sched_setparam 154
#define NR_compat_sched_getparam 155
#define NR_compat_sched_setscheduler 156
#define NR_compat_sched_getscheduler 157
#define NR_compat_sched_yield 158
#define NR_compat_sched_get_priority_max 159
#define NR_compat_sched_get_priority_min 160
#define NR_compat_sched_rr_get_interval 161
#define NR_compat_nanosleep 162
#define NR_compat_mremap 163
#define NR_compat_setresuid 164
#define NR_compat_getresuid 165
#define NR_compat_poll 168
#define NR_compat_nfsservctl 169
#define NR_compat_setresgid 170
#define NR_compat_getresgid 171
#define NR_compat_prctl 172
#define NR_compat_rt_sigreturn 173
#define NR_compat_rt_sigaction 174
#define NR_compat_rt_sigprocmask 175
#define NR_compat_rt_sigpending 176
#define NR_compat_rt_sigtimedwait 177
#define NR_compat_rt_sigqueueinfo 178
#define NR_compat_rt_sigsuspend 179
#define NR_compat_pread64 180
#define NR_compat_pwrite64 181
#define NR_compat_chown 182
#define NR_compat_getcwd 183
#define NR_compat_capget 184
#define NR_compat_capset 185
#define NR_compat_sigaltstack 186
#define NR_compat_sendfile 187
#define NR_compat_vfork 190
#define NR_compat_ugetrlimit 191
#define NR_compat_mmap2 192
#define NR_compat_truncate64 193
#define NR_compat_ftruncate64 194
#define NR_compat_stat64 195
#define NR_compat_lstat64 196
#define NR_compat_fstat64 197
#define NR_compat_lchown32 198
#define NR_compat_getuid32 199
#define NR_compat_getgid32 200
#define NR_compat_geteuid32 201
#define NR_compat_getegid32 202
#define NR_compat_setreuid32 203
#define NR_compat_setregid32 204
#define NR_compat_getgroups32 205
#define NR_compat_setgroups32 206
#define NR_compat_fchown32 207
#define NR_compat_setresuid32 208
#define NR_compat_getresuid32 209
#define NR_compat_setresgid32 210
#define NR_compat_getresgid32 211
#define NR_compat_chown32 212
#define NR_compat_setuid32 213
#define NR_compat_setgid32 214
#define NR_compat_setfsuid32 215
#define NR_compat_setfsgid32 216
#define NR_compat_getdents64 217
#define NR_compat_pivot_root 218
#define NR_compat_mincore 219
#define NR_compat_madvise 220
#define NR_compat_fcntl64 221
#define NR_compat_gettid 224
#define NR_compat_readahead 225
#define NR_compat_setxattr 226
#define NR_compat_lsetxattr 227
#define NR_compat_fsetxattr 228
#define NR_compat_getxattr 229
#define NR_compat_lgetxattr 230
#define NR_compat_fgetxattr 231
#define NR_compat_listxattr 232
#define NR_compat_llistxattr 233
#define NR_compat_flistxattr 234
#define NR_compat_removexattr 235
#define NR_compat_lremovexattr 236
#define NR_compat_fremovexattr 237
#define NR_compat_tkill 238
#define NR_compat_sendfile64 239
#define NR_compat_futex 240
#define NR_compat_sched_setaffinity 241
#define NR_compat_sched_getaffinity 242
#define NR_compat_io_setup 243
#define NR_compat_io_destroy 244
#define NR_compat_io_getevents 245
#define NR_compat_io_submit 246
#define NR_compat_io_cancel 247
#define NR_compat_exit_group 248
#define NR_compat_lookup_dcookie 249
#define NR_compat_epoll_create 250
#define NR_compat_epoll_ctl 251
#define NR_compat_epoll_wait 252
#define NR_compat_remap_file_pages 253
#define NR_compat_set_tid_address 256
#define NR_compat_timer_create 257
#define NR_compat_timer_settime 258
#define NR_compat_timer_gettime 259
#define NR_compat_timer_getoverrun 260
#define NR_compat_timer_delete 261
#define NR_compat_clock_settime 262
#define NR_compat_clock_gettime 263
#define NR_compat_clock_getres 264
#define NR_compat_clock_nanosleep 265
#define NR_compat_statfs64 266
#define NR_compat_fstatfs64 267
#define NR_compat_tgkill 268
#define NR_compat_utimes 269
#define NR_compat_arm_fadvise64_64 270
#define NR_compat_pciconfig_iobase 271
#define NR_compat_pciconfig_read 272
#define NR_compat_pciconfig_write 273
#define NR_compat_mq_open 274
#define NR_compat_mq_unlink 275
#define NR_compat_mq_timedsend 276
#define NR_compat_mq_timedreceive 277
#define NR_compat_mq_notify 278
#define NR_compat_mq_getsetattr 279
#define NR_compat_waitid 280
#define NR_compat_socket 281
#define NR_compat_bind 282
#define NR_compat_connect 283
#define NR_compat_listen 284
#define NR_compat_accept 285
#define NR_compat_getsockname 286
#define NR_compat_getpeername 287
#define NR_compat_socketpair 288
#define NR_compat_send 289
#define NR_compat_sendto 290
#define NR_compat_recv 291
#define NR_compat_recvfrom 292
#define NR_compat_shutdown 293
#define NR_compat_setsockopt 294
#define NR_compat_getsockopt 295
#define NR_compat_sendmsg 296
#define NR_compat_recvmsg 297
#define NR_compat_semop 298
#define NR_compat_semget 299
#define NR_compat_semctl 300
#define NR_compat_msgsnd 301
#define NR_compat_msgrcv 302
#define NR_compat_msgget 303
#define NR_compat_msgctl 304
#define NR_compat_shmat 305
#define NR_compat_shmdt 306
#define NR_compat_shmget 307
#define NR_compat_shmctl 308
#define NR_compat_add_key 309
#define NR_compat_request_key 310
#define NR_compat_keyctl 311
#define NR_compat_semtimedop 312
#define NR_compat_vserver 313
#define NR_compat_ioprio_set 314
#define NR_compat_ioprio_get 315
#define NR_compat_inotify_init 316
#define NR_compat_inotify_add_watch 317
#define NR_compat_inotify_rm_watch 318
#define NR_compat_mbind 319
#define NR_compat_get_mempolicy 320
#define NR_compat_set_mempolicy 321
#define NR_compat_openat 322
#define NR_compat_mkdirat 323
#define NR_compat_mknodat 324
#define NR_compat_fchownat 325
#define NR_compat_futimesat 326
#define NR_compat_fstatat64 327
#define NR_compat_unlinkat 328
#define NR_compat_renameat 329
#define NR_compat_linkat 330
#define NR_compat_symlinkat 331
#define NR_compat_readlinkat 332
#define NR_compat_fchmodat 333
#define NR_compat_faccessat 334
#define NR_compat_pselect6 335
#define NR_compat_ppoll 336
#define NR_compat_unshare 337
#define NR_compat_set_robust_list 338
#define NR_compat_get_robust_list 339
#define NR_compat_splice 340
#define NR_compat_sync_file_range2 341
#define NR_compat_tee 342
#define NR_compat_vmsplice 343
#define NR_compat_move_pages 344
#define NR_compat_getcpu 345
#define NR_compat_epoll_pwait 346
#define NR_compat_kexec_load 347
#define NR_compat_utimensat 348
#define NR_compat_signalfd 349
#define NR_compat_timerfd_create 350
#define NR_compat_eventfd 351
#define NR_compat_fallocate 352
#define NR_compat_timerfd_settime 353
#define NR_compat_timerfd_gettime 354
#define NR_compat_signalfd4 355
#define NR_compat_eventfd2 356
#define NR_compat_epoll_create1 357
#define NR_compat_dup3 358
#define NR_compat_pipe2 359
#define NR_compat_inotify_init1 360
#define NR_compat_preadv 361
#define NR_compat_pwritev 362
#define NR_compat_rt_tgsigqueueinfo 363
#define NR_compat_perf_event_open 364
#define NR_compat_recvmmsg 365
#define NR_compat_accept4 366
#define NR_compat_fanotify_init 367
#define NR_compat_fanotify_mark 368
#define NR_compat_prlimit64 369
#define NR_compat_name_to_handle_at 370
#define NR_compat_open_by_handle_at 371
#define NR_compat_clock_adjtime 372
#define NR_compat_syncfs 373
#define NR_compat_sendmmsg 374
#define NR_compat_setns 375
#define NR_compat_process_vm_readv 376
#define NR_compat_process_vm_writev 377
#define NR_compat_kcmp 378
#define NR_compat_finit_module 379
#define NR_compat_sched_setattr 380
#define NR_compat_sched_getattr 381
#define NR_compat_renameat2 382
#define NR_compat_seccomp 383
#define NR_compat_getrandom 384
#define NR_compat_memfd_create 385
#define NR_compat_bpf 386


#define NR64_compat_io_setup 0
#define NR64_compat_io_destroy 1
#define NR64_compat_io_submit 2
#define NR64_compat_io_cancel 3
#define NR64_compat_io_getevents 4
#define NR64_compat_setxattr 5
#define NR64_compat_lsetxattr 6
#define NR64_compat_fsetxattr 7
#define NR64_compat_getxattr 8
#define NR64_compat_lgetxattr 9
#define NR64_compat_fgetxattr 10
#define NR64_compat_listxattr 11
#define NR64_compat_llistxattr 12
#define NR64_compat_flistxattr 13
#define NR64_compat_removexattr 14
#define NR64_compat_lremovexattr 15
#define NR64_compat_fremovexattr 16
#define NR64_compat_getcwd 17
#define NR64_compat_lookup_dcookie 18
#define NR64_compat_eventfd2 19
#define NR64_compat_epoll_create1 20
#define NR64_compat_epoll_ctl 21
#define NR64_compat_epoll_pwait 22
#define NR64_compat_dup 23
#define NR64_compat_dup3 24
#define NR64_compat_fcntl 25
#define NR64_compat_inotify_init1 26
#define NR64_compat_inotify_add_watch 27
#define NR64_compat_inotify_rm_watch 28
#define NR64_compat_ioctl 29
#define NR64_compat_ioprio_set 30
#define NR64_compat_ioprio_get 31
#define NR64_compat_flock 32
#define NR64_compat_mknodat 33
#define NR64_compat_mkdirat 34
#define NR64_compat_unlinkat 35
#define NR64_compat_symlinkat 36
#define NR64_compat_linkat 37
#define NR64_compat_renameat 38
#define NR64_compat_umount2 39
#define NR64_compat_mount 40
#define NR64_compat_pivot_root 41
#define NR64_compat_nfsservctl 42
#define NR64_compat_statfs 43
#define NR64_compat_fstatfs 44
#define NR64_compat_truncate 45
#define NR64_compat_ftruncate 46
#define NR64_compat_fallocate 47
#define NR64_compat_faccessat 48
#define NR64_compat_chdir 49
#define NR64_compat_fchdir 50
#define NR64_compat_chroot 51
#define NR64_compat_fchmod 52
#define NR64_compat_fchmodat 53
#define NR64_compat_fchownat 54
#define NR64_compat_fchown 55
#define NR64_compat_openat 56
#define NR64_compat_close 57
#define NR64_compat_vhangup 58
#define NR64_compat_pipe2 59
#define NR64_compat_quotactl 60
#define NR64_compat_getdents64 61
#define NR64_compat_lseek 62
#define NR64_compat_read 63
#define NR64_compat_write 64
#define NR64_compat_readv 65
#define NR64_compat_writev 66
#define NR64_compat_pread64 67
#define NR64_compat_pwrite64 68
#define NR64_compat_preadv 69
#define NR64_compat_pwritev 70
#define NR64_compat_sendfile 71
#define NR64_compat_pselect6 72
#define NR64_compat_ppoll 73
#define NR64_compat_signalfd4 74
#define NR64_compat_vmsplice 75
#define NR64_compat_splice 76
#define NR64_compat_tee 77
#define NR64_compat_readlinkat 78
#define NR64_compat_fstatat 79
#define NR64_compat_fstat 80
#define NR64_compat_sync 81
#define NR64_compat_fsync 82
#define NR64_compat_fdatasync 83
#define NR64_compat_sync_file_range2 84
#define NR64_compat_sync_file_range 84
#define NR64_compat_timerfd_create 85
#define NR64_compat_timerfd_settime 86
#define NR64_compat_timerfd_gettime 87
#define NR64_compat_utimensat 88
#define NR64_compat_acct 89
#define NR64_compat_capget 90
#define NR64_compat_capset 91
#define NR64_compat_personality 92
#define NR64_compat_exit 93
#define NR64_compat_exit_group 94
#define NR64_compat_waitid 95
#define NR64_compat_set_tid_address 96
#define NR64_compat_unshare 97
#define NR64_compat_futex 98
#define NR64_compat_set_robust_list 99
#define NR64_compat_get_robust_list 100
#define NR64_compat_nanosleep 101
#define NR64_compat_getitimer 102
#define NR64_compat_setitimer 103
#define NR64_compat_kexec_load 104
#define NR64_compat_init_module 105
#define NR64_compat_delete_module 106
#define NR64_compat_timer_create 107
#define NR64_compat_timer_gettime 108
#define NR64_compat_timer_getoverrun 109
#define NR64_compat_timer_settime 110
#define NR64_compat_timer_delete 111
#define NR64_compat_clock_settime 112
#define NR64_compat_clock_gettime 113
#define NR64_compat_clock_getres 114
#define NR64_compat_clock_nanosleep 115
#define NR64_compat_syslog 116
#define NR64_compat_ptrace 117
#define NR64_compat_sched_setparam 118
#define NR64_compat_sched_setscheduler 119
#define NR64_compat_sched_getscheduler 120
#define NR64_compat_sched_getparam 121
#define NR64_compat_sched_setaffinity 122
#define NR64_compat_sched_getaffinity 123
#define NR64_compat_sched_yield 124
#define NR64_compat_sched_get_priority_max 125
#define NR64_compat_sched_get_priority_min 126
#define NR64_compat_sched_rr_get_interval 127
#define NR64_compat_restart_syscall 128
#define NR64_compat_kill 129
#define NR64_compat_tkill 130
#define NR64_compat_tgkill 131
#define NR64_compat_sigaltstack 132
#define NR64_compat_rt_sigsuspend 133
#define NR64_compat_rt_sigaction 134
#define NR64_compat_rt_sigprocmask 135
#define NR64_compat_rt_sigpending 136
#define NR64_compat_rt_sigtimedwait 137
#define NR64_compat_rt_sigqueueinfo 138
#define NR64_compat_rt_sigreturn 139
#define NR64_compat_setpriority 140
#define NR64_compat_getpriority 141
#define NR64_compat_reboot 142
#define NR64_compat_setregid 143
#define NR64_compat_setgid 144
#define NR64_compat_setreuid 145
#define NR64_compat_setuid 146
#define NR64_compat_setresuid 147
#define NR64_compat_getresuid 148
#define NR64_compat_setresgid 149
#define NR64_compat_getresgid 150
#define NR64_compat_setfsuid 151
#define NR64_compat_setfsgid 152
#define NR64_compat_times 153
#define NR64_compat_setpgid 154
#define NR64_compat_getpgid 155
#define NR64_compat_getsid 156
#define NR64_compat_setsid 157
#define NR64_compat_getgroups 158
#define NR64_compat_setgroups 159
#define NR64_compat_uname 160
#define NR64_compat_sethostname 161
#define NR64_compat_setdomainname 162
#define NR64_compat_getrlimit 163
#define NR64_compat_setrlimit 164
#define NR64_compat_getrusage 165
#define NR64_compat_umask 166
#define NR64_compat_prctl 167
#define NR64_compat_getcpu 168
#define NR64_compat_gettimeofday 169
#define NR64_compat_settimeofday 170
#define NR64_compat_adjtimex 171
#define NR64_compat_getpid 172
#define NR64_compat_getppid 173
#define NR64_compat_getuid 174
#define NR64_compat_geteuid 175
#define NR64_compat_getgid 176
#define NR64_compat_getegid 177
#define NR64_compat_gettid 178
#define NR64_compat_sysinfo 179
#define NR64_compat_mq_open 180
#define NR64_compat_mq_unlink 181
#define NR64_compat_mq_timedsend 182
#define NR64_compat_mq_timedreceive 183
#define NR64_compat_mq_notify 184
#define NR64_compat_mq_getsetattr 185
#define NR64_compat_msgget 186
#define NR64_compat_msgctl 187
#define NR64_compat_msgrcv 188
#define NR64_compat_msgsnd 189
#define NR64_compat_semget 190
#define NR64_compat_semctl 191
#define NR64_compat_semtimedop 192
#define NR64_compat_semop 193
#define NR64_compat_shmget 194
#define NR64_compat_shmctl 195
#define NR64_compat_shmat 196
#define NR64_compat_shmdt 197
#define NR64_compat_socket 198
#define NR64_compat_socketpair 199
#define NR64_compat_bind 200
#define NR64_compat_listen 201
#define NR64_compat_accept 202
#define NR64_compat_connect 203
#define NR64_compat_getsockname 204
#define NR64_compat_getpeername 205
#define NR64_compat_sendto 206
#define NR64_compat_recvfrom 207
#define NR64_compat_setsockopt 208
#define NR64_compat_getsockopt 209
#define NR64_compat_shutdown 210
#define NR64_compat_sendmsg 211
#define NR64_compat_recvmsg 212
#define NR64_compat_readahead 213
#define NR64_compat_brk 214
#define NR64_compat_munmap 215
#define NR64_compat_mremap 216
#define NR64_compat_add_key 217
#define NR64_compat_request_key 218
#define NR64_compat_keyctl 219
#define NR64_compat_clone 220
#define NR64_compat_execve 221
#define NR64_compat_mmap 222
#define NR64_compat_fadvise64 223
#define NR64_compat_swapon 224
#define NR64_compat_swapoff 225
#define NR64_compat_mprotect 226
#define NR64_compat_msync 227
#define NR64_compat_mlock 228
#define NR64_compat_munlock 229
#define NR64_compat_mlockall 230
#define NR64_compat_munlockall 231
#define NR64_compat_mincore 232
#define NR64_compat_madvise 233
#define NR64_compat_remap_file_pages 234
#define NR64_compat_mbind 235
#define NR64_compat_get_mempolicy 236
#define NR64_compat_set_mempolicy 237
#define NR64_compat_migrate_pages 238
#define NR64_compat_move_pages 239
#define NR64_compat_rt_tgsigqueueinfo 240
#define NR64_compat_perf_event_open 241
#define NR64_compat_accept4 242
#define NR64_compat_recvmmsg 243
#define NR64_compat_arch_specific_syscall 244
#define NR64_compat_wait4 260
#define NR64_compat_prlimit64 261
#define NR64_compat_fanotify_init 262
#define NR64_compat_fanotify_mark 263
#define NR64_compat_name_to_handle_at 264
#define NR64_compat_open_by_handle_at 265
#define NR64_compat_clock_adjtime 266
#define NR64_compat_syncfs 267
#define NR64_compat_setns 268
#define NR64_compat_sendmmsg 269
#define NR64_compat_process_vm_readv 270
#define NR64_compat_process_vm_writev 271
#define NR64_compat_kcmp 272
#define NR64_compat_finit_module 273
#define NR64_compat_sched_setattr 274
#define NR64_compat_sched_getattr 275
#define NR64_compat_renameat2 276
#define NR64_compat_seccomp 277
#define NR64_compat_getrandom 278
#define NR64_compat_memfd_create 279
#define NR64_compat_bpf 280
#define NR64_compat_syscalls 281


#define ARG_UNKNOWN 0
#define ARG_FD 1
#define ARG_PID 2
#define ARG_ADDR 3
#define ARG_PATH 4
#define ARG_DATA 5
#define ARG_FDPAIR 6
#define ARG_ARGV 100

static DEFINE_MUTEX(syscall_mutex);


static u8 compat_syscall_arg_type[NR_compat_syscalls][7] = {
    [0 ... NR_compat_syscalls - 1][0 ... 6] = 0,
	[NR_compat_execve][1] = ARG_ARGV,
// -----------------------------------------------
	[NR_compat_read][0] = ARG_FD,
	[NR_compat_readv][0] = ARG_FD,
	[NR_compat_pread64][0] = ARG_FD,
	[NR_compat_preadv][0] = ARG_FD,
    [NR_compat_write][0] = ARG_FD,
	[NR_compat_writev][0] = ARG_FD,
	[NR_compat_pwrite64][0] = ARG_FD,
	[NR_compat_pwritev][0] = ARG_FD,
	[NR_compat_lseek][0] = ARG_FD,
	[NR_compat__llseek][0] = ARG_FD,
    [NR_compat_ioctl][0] = ARG_FD,
	[NR_compat_sendfile][0] = ARG_FD,
	[NR_compat_sendfile64][0] = ARG_FD,
	[NR_compat_fcntl][0] = ARG_FD,
	[NR_compat_fcntl64][0] = ARG_FD,
// -----------------------------------------------
	[NR_compat_open][6] = ARG_FD,
	[NR_compat_openat][6] = ARG_FD,
	[NR_compat_creat][6] = ARG_FD,
	[NR_compat_dup][0] = ARG_FD,
	[NR_compat_dup2][0] = ARG_FD,
	[NR_compat_dup3][0] = ARG_FD,
	[NR_compat_socket][6] = ARG_FD,
	[NR_compat_socketpair][3] = ARG_FDPAIR,
	[NR_compat_pipe][0] = ARG_FDPAIR,
	[NR_compat_pipe2][0] = ARG_FDPAIR,
	[NR_compat_inotify_init][6] = ARG_FD,
	[NR_compat_inotify_init1][6] = ARG_FD,
	[NR_compat_eventfd][6] = ARG_FD,
	[NR_compat_eventfd2][6] = ARG_FD,
	// [NR_compat_epoll_create][6] = ARG_FD,
	// [NR_compat_epoll_create1][6] = ARG_FD,
// -----------------------------------------------
	[NR_compat_open][0] = ARG_PATH,
    [NR_compat_execve][0] = ARG_PATH,
	[NR_compat_chmod][0] = ARG_PATH,
	[NR_compat_truncate][0] = ARG_PATH,
	[NR_compat_truncate64][0] = ARG_PATH,
	[NR_compat_link][0] = ARG_PATH,
	[NR_compat_link][1] = ARG_PATH,
	[NR_compat_linkat][1] = ARG_PATH,
	[NR_compat_linkat][2] = ARG_PATH,
	[NR_compat_stat][0] = ARG_PATH,
	[NR_compat_stat64][0] = ARG_PATH,
	[NR_compat_lstat][0] = ARG_PATH,
	[NR_compat_lstat64][0] = ARG_PATH,
    [NR_compat_setxattr][0] = ARG_PATH,
    [NR_compat_lsetxattr][0] = ARG_PATH,
	[NR_compat_statfs][0] = ARG_PATH,
    [NR_compat_statfs64][0] = ARG_PATH,
    [NR_compat_inotify_add_watch][1] = ARG_PATH,
	[NR_compat_symlink][0] = ARG_PATH,
	[NR_compat_symlinkat][0] = ARG_PATH,
    [NR_compat_openat][1] = ARG_PATH,
	[NR_compat_mkdir][0] = ARG_PATH,
    [NR_compat_mkdirat][1] = ARG_PATH,
	[NR_compat_chown][0] = ARG_PATH,
	[NR_compat_chown32][0] = ARG_PATH,
	[NR_compat_lchown][0] = ARG_PATH,
	[NR_compat_lchown32][0] = ARG_PATH,
    [NR_compat_fchownat][1] = ARG_PATH,
    [NR_compat_fstatat64][1] = ARG_PATH,
	[NR_compat_unlink][0] = ARG_PATH,
    [NR_compat_unlinkat][1] = ARG_PATH,
	[NR_compat_rename][0] = ARG_PATH,
	[NR_compat_rename][1] = ARG_PATH,
    [NR_compat_renameat][1] = ARG_PATH,
    [NR_compat_renameat][3] = ARG_PATH,
	[NR_compat_renameat2][1] = ARG_PATH,
	[NR_compat_renameat2][3] = ARG_PATH,
	[NR_compat_readlink][0] = ARG_PATH,
    [NR_compat_readlinkat][1] = ARG_PATH,
    [NR_compat_fchmodat][1] = ARG_PATH,
	[NR_compat_access][0] = ARG_PATH,
    [NR_compat_faccessat][1] = ARG_PATH,
	[NR_compat_getxattr][0] = ARG_PATH,
	[NR_compat_lgetxattr][0] = ARG_PATH,
	[NR_compat_listxattr][0] = ARG_PATH,
	[NR_compat_llistxattr][0] = ARG_PATH,
	[NR_compat_removexattr][0] = ARG_PATH,
	[NR_compat_lremovexattr][0] = ARG_PATH,
	[NR_compat_mknod][0] = ARG_PATH,
	[NR_compat_mknodat][1] = ARG_PATH,
	[NR_compat_creat][0] = ARG_PATH,
	[NR_compat_name_to_handle_at][1] = ARG_PATH,
	[NR_compat_memfd_create][0] = ARG_PATH,
};

static u8 compat64_syscall_arg_type[NR64_compat_syscalls][7] = {
	[NR64_compat_execve][1] = ARG_ARGV,
// -----------------------------------------------
	[NR64_compat_read][0] = ARG_FD,
	[NR64_compat_readv][0] = ARG_FD,
	[NR64_compat_pread64][0] = ARG_FD,
	[NR64_compat_preadv][0] = ARG_FD,
    [NR64_compat_write][0] = ARG_FD,
	[NR64_compat_writev][0] = ARG_FD,
	[NR64_compat_pwrite64][0] = ARG_FD,
	[NR64_compat_pwritev][0] = ARG_FD,
	[NR64_compat_lseek][0] = ARG_FD,
	[NR64_compat_ioctl][0] = ARG_FD,
	[NR64_compat_sendfile][0] = ARG_FD,
	[NR64_compat_fcntl][0] = ARG_FD,
// -----------------------------------------------
	[NR64_compat_openat][6] = ARG_FD,
	[NR64_compat_dup][0] = ARG_FD,
	[NR64_compat_dup3][0] = ARG_FD,
	[NR64_compat_socket][6] = ARG_FD,
	[NR64_compat_socketpair][3] = ARG_FDPAIR,
	[NR64_compat_pipe2][0] = ARG_FDPAIR,
	[NR64_compat_inotify_init1][6] = ARG_FD,
	[NR64_compat_eventfd2][6] = ARG_FD,
	// [NR64_compat_epoll_create1][6] = ARG_FD,
// -----------------------------------------------
	[NR64_compat_execve][0] = ARG_PATH,
	[NR64_compat_setxattr][0] = ARG_PATH,
	[NR64_compat_lsetxattr][0] = ARG_PATH,
	[NR64_compat_getxattr][0] = ARG_PATH,
	[NR64_compat_lgetxattr][0] = ARG_PATH,
	[NR64_compat_linkat][1] = ARG_PATH,
	[NR64_compat_linkat][2] = ARG_PATH,
	[NR64_compat_inotify_add_watch][1] = ARG_PATH,
	[NR64_compat_symlinkat][0] = ARG_PATH,
	[NR64_compat_openat][1] = ARG_PATH,
	[NR64_compat_mkdirat][1] = ARG_PATH,
	[NR64_compat_fchownat][1] = ARG_PATH,
	[NR64_compat_unlinkat][1] = ARG_PATH,
	[NR64_compat_renameat][1] = ARG_PATH,
	[NR64_compat_renameat][3] = ARG_PATH,
	[NR64_compat_renameat2][1] = ARG_PATH,
	[NR64_compat_renameat2][3] = ARG_PATH,
	[NR64_compat_readlinkat][1] = ARG_PATH,
	[NR64_compat_fchmodat][1] = ARG_PATH,
	[NR64_compat_faccessat][1] = ARG_PATH,
	[NR64_compat_listxattr][0] = ARG_PATH,
	[NR64_compat_llistxattr][0] = ARG_PATH,
	[NR64_compat_removexattr][0] = ARG_PATH,
	[NR64_compat_lremovexattr][0] = ARG_PATH,
	[NR64_compat_mknodat][1] = ARG_PATH,
	[NR64_compat_statfs][0] = ARG_PATH,
	[NR64_compat_truncate][0] = ARG_PATH,
	[NR64_compat_fstatat][1] = ARG_PATH,
	[NR64_compat_name_to_handle_at][1] = ARG_PATH,
	[NR64_compat_memfd_create][0] = ARG_PATH,
};


static char* testlog_buf[1024];
static int testlog_buf_size = 0;
static size_t testlog_len = 0;
static rwlock_t testlog_rwlock = __RW_LOCK_UNLOCKED();

// #define BUFFER_LEN (1<<20) // 1MB
#define BUFFER_LEN (1<<25) // 32MB

static int extend_testlog_buffer(void) {
	void *buf = NULL;
	
	// if (testlog_buf_size < 1024)
	if (testlog_buf_size < 32)
		// buf = kmalloc(BUFFER_LEN, GFP_KERNEL);
		buf = vmalloc(BUFFER_LEN);

	if (buf != NULL) {
		pr_warn("syscall_test_in_extent");
		testlog_buf[testlog_buf_size++] = buf;
		return 0;
	} else {
		pr_info("syscall_test: init buffer failed\n");
		return -1;
	}
}

static void testlog_write_locked(char *data, size_t size) {
	size_t start, end, now;

	while (testlog_len + size > testlog_buf_size * BUFFER_LEN) {
		if (extend_testlog_buffer() != 0) {
			// size = testlog_buf_size * BUFFER_LEN - testlog_len;
			// break;
			return;
		}
	}
	
	start = testlog_len;
	end = testlog_len + size;
	for (now = start; now < end; ) {
		int bno = now / BUFFER_LEN;
		size_t next = (bno + 1) * BUFFER_LEN;
		if (next > end)
			next = end;

		memcpy(testlog_buf[bno] + now % BUFFER_LEN, data + (now - start), next - now);

		now = next;
	}

	testlog_len = now;
}

static ssize_t testlog_read_locked(struct file *file, char __user *buf, size_t size, loff_t *ppos, size_t len) {
	loff_t start = *ppos, end = *ppos + size;
	loff_t now;
	int err;

	if (end > len)
		end = len;

	if (start >= end)
		return 0;

	for (now = start; now < end; ) {
		int bno = now / BUFFER_LEN;
		loff_t next = (bno + 1) * BUFFER_LEN;
		if (next > end)
			next = end;

		err = copy_to_user(buf + (now - start), testlog_buf[bno] + now % BUFFER_LEN, next - now);
		if (err) {
			pr_warn("syscall_test: test_log read failed\n");
			return -EFAULT;
		}

		now = next;
	}

	*ppos = end;
	return end - start;
}

static ssize_t testlog_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
	unsigned long flags;
	size_t len;
	read_lock_irqsave(&testlog_rwlock, flags);
	len = testlog_len;
	read_unlock_irqrestore(&testlog_rwlock, flags);
	return testlog_read_locked(file, buf, size, ppos, len);
}

static void testlog_write(void *data, size_t size) {
	// unsigned long flags;
	// write_lock_irqsave(&testlog_rwlock, flags);
	mutex_lock(&syscall_mutex);
	testlog_write_locked((char *) data, size);
	mutex_unlock(&syscall_mutex);
	// write_unlock_irqrestore(&testlog_rwlock, flags);
}


static void testlog_write2(void *data, size_t size, void *data2, size_t size2) {
	// unsigned long flags;
	// write_lock_irqsave(&testlog_rwlock, flags);
	mutex_lock(&syscall_mutex);
	testlog_write_locked((char *) data, size);
	testlog_write_locked((char *) data2, size2);
	mutex_unlock(&syscall_mutex);
	// write_unlock_irqrestore(&testlog_rwlock, flags);
}


static const struct file_operations meminfo_proc_fops = {
	.read		= testlog_read,
};

static int __init proc_testlog_init(void)
{
	proc_create("testlog", 0, NULL, &meminfo_proc_fops);
	return 0;
}
fs_initcall(proc_testlog_init);

#define LOG_SCINFO 1
#define LOG_SCDATA 2
#define LOG_SCSTART 3
#define LOG_SCFD 4
#define LOG_SCSTACK 5
#define LOG_SCMEM 6


struct testlog_scinfo {
	int size;
	int type;
	int id;
	pid_t pid;
	u64 syscallno;
	u64 args[6];
	u64 ret;
};


struct testlog_scdata {
	int size;
	int type;
	int id;
	int pos;
	u64 syscallno;
};


struct testlog_scstart {
	int size;
	int type;
	pid_t pid;
	bool is32;
};

struct testlog_scfd {
	int size;
	int type;
	pid_t pid;
	unsigned int fd;
};

/*
#define MAX_STACK_SIZE 17

struct testlog_scstack {
	int size;
	int type;
	int id;
	s32 addr[MAX_STACK_SIZE];
};
*/

struct testlog_scmem {
	int size;
	int type;
	pid_t pid;
	u32 start, end;
};


static void output_scinfo(struct pt_regs *regs, pid_t pid, int test_id, int call_pos) {
	struct testlog_scinfo scinfo;
	scinfo.size = sizeof(struct testlog_scinfo);
	scinfo.type = LOG_SCINFO;
	scinfo.pid = pid;
	scinfo.id = test_id;
	scinfo.syscallno = regs->syscallno;
	scinfo.args[0] = regs->orig_x0;
	scinfo.args[1] = regs->regs[1];
	scinfo.args[2] = regs->regs[2];
	scinfo.args[3] = regs->regs[3];
	scinfo.args[4] = regs->regs[4];
	scinfo.args[5] = regs->regs[6];
	scinfo.ret = regs->regs[0];
	if (call_pos == 0)
		scinfo.ret = -1;
	testlog_write(&scinfo, sizeof(scinfo));
}




static void output_scdata(void *data, size_t len, int pos, int test_id, int syscallno) {
	struct testlog_scdata scdata;
	scdata.size = sizeof(struct testlog_scdata) + len;
	scdata.type = LOG_SCDATA;
	scdata.id = test_id;
	scdata.pos = pos;
	scdata.syscallno = syscallno;
	testlog_write2(&scdata, sizeof(scdata), data, len);
}


extern void output_scfd(pid_t pid, unsigned int fd, struct file *file) {
	unsigned long flags;
	struct testlog_scfd scfd;
	char *path;
	int pathlen;
	static char buffer[PATH_MAX];

	write_lock_irqsave(&testlog_rwlock, flags);
	path = d_path(&file->f_path, buffer, PATH_MAX);
	if (IS_ERR(path))
		path = "";
	pathlen = strlen(path) + 1;
	scfd.size = sizeof (struct testlog_scfd) + pathlen;
	scfd.type = LOG_SCFD;
	scfd.pid = pid;
	scfd.fd = fd;
	testlog_write_locked((char *)&scfd, sizeof(scfd));
	testlog_write_locked(path, pathlen);
	write_unlock_irqrestore(&testlog_rwlock, flags);
}

extern void output_scmem(pid_t pid, struct vm_area_struct *vma) {
	unsigned long flags;
	struct testlog_scmem scmem;
	struct file *file = vma->vm_file;
	char *path;
	int pathlen;
	static char buffer[PATH_MAX];

	if (!file)
	    return;

	write_lock_irqsave(&testlog_rwlock, flags);
	path = d_path(&file->f_path, buffer, PATH_MAX);
	if (IS_ERR(path))
		path = "";
	pathlen = strlen(path) + 1;
	scmem.size = sizeof (struct testlog_scmem) + pathlen;
	scmem.type = LOG_SCMEM;
	scmem.pid = pid;
	scmem.start = (u32) vma->vm_start;
	scmem.end = (u32) vma->vm_end;
	testlog_write_locked((char *)&scmem, sizeof(scmem));
	testlog_write_locked(path, pathlen);
	write_unlock_irqrestore(&testlog_rwlock, flags);
}

extern void test_syscall_start_log(void) {
	struct testlog_scstart scstart;
	struct task_struct *t;
	pid_t pid = task_pid_nr(current);
	bool is32 = test_thread_flag(TIF_32BIT);
	struct files_struct *files = current->files;
	// struct mm_struct *mm = current->mm;

	mutex_init(&syscall_mutex);

	scstart.size = sizeof (struct testlog_scstart);
	scstart.type = LOG_SCSTART;
	scstart.pid = pid;
	scstart.is32 = is32;
	testlog_write(&scstart, sizeof(scstart));

	
	if (files) {
		struct fdtable *fdt = files_fdtable(files);
		unsigned int fd;

		for (fd = 0; fd < files_fdtable(files)->max_fds; fd++) {
			struct file *file = fdt->fd[fd];
			if (file)
				output_scfd(pid, fd, file);
		}
	}

	pr_info("syscall_test: start\n");
	pr_info("syscall_test: PID: %d\n", task_pid_nr(current));

	if (is32)
		pr_info("syscall_test: 32bit process detected\n");
	else
		pr_info("syscall_test: 64bit process detected\n");

	rcu_read_lock();
	for_each_thread(current, t) {
		pr_info("syscall_test: thread: %d\n", task_pid_nr(t));
	}
	rcu_read_unlock();
}

// 2
static void test_syscall_log(struct pt_regs *regs, int call_pos)
{
	// atomic id
	static atomic_t test_atomic_id = ATOMIC_INIT(0);
	// test 32bit
	bool is32 = test_thread_flag(TIF_32BIT);
	// get pid
	pid_t pid = task_pid_nr(current);
	// get system call number
	u64 no = regs->syscallno;
	// add id
	int test_id = atomic_add_return(1, &test_atomic_id);
	int i;
	// output parameter and retval of system call
	// output_scinfo(regs, pid, test_id, call_pos);

	if (is32) {
		if (no <= 386 && no > 0){
			// process specific parameters
			for (i = 0; i <= 6; ++i) {
				u64 arg = i == 6 ? regs->regs[0] : (i == 0 ? regs->orig_x0 : regs->regs[i]);
				
				switch(compat_syscall_arg_type[no][i]) {
				case ARG_FD: {
					output_scinfo(regs, pid, test_id, call_pos);
					break;
				}
				case ARG_PATH: {
					char *path = NULL;
					int path_len;
					path = kmalloc(PATH_MAX, GFP_KERNEL);

					if (unlikely(!path)) {
						pr_warn("syscall_test: %d: [%d] kmalloc failed\n", pid, test_id);
					}
					else {	
						if (access_ok(VERIFY_READ, compat_ptr((compat_uptr_t) arg), PATH_MAX - 1)){
							path_len = strncpy_from_user(path, compat_ptr((compat_uptr_t) arg), PATH_MAX - 1);
							path[path_len] = '\0';
							output_scdata(path, path_len + 1, i, test_id, no);
						}
						else{
							pr_warn("syscall_test: error address: %p\n", compat_ptr((compat_uptr_t) arg));
						}
					}
					if (path) {
						kfree(path);
						path = NULL;
					}
					break;
				}
				case ARG_ARGV: {
					compat_uptr_t argv = arg;
					char *output = kmalloc(4096, GFP_KERNEL);
					int size = 0;
					bool err = false;

					if (unlikely(!output)) {
						pr_warn("syscall_test: %d: [%d] kmalloc failed\n", pid, test_id);
					} else {
						compat_uptr_t ptr;
						for ( ; ; ++argv) {
							int len;
							if (copy_from_user(&ptr, compat_ptr(argv), sizeof(ptr))) {
								err = true;
								break;
							}
							if (!ptr)
								break;
							len = strnlen_user(compat_ptr(ptr), MAX_ARG_STRLEN);
							if (len > MAX_ARG_STRLEN) {
								err = true;
								break;
							}
							--len;
							if (len <= 0)
								continue;
							if (size > 0 && size < 4095)
								output[size++] = ' ';
							if (len > 4095 - size)
								len = 4095 - size;
							if (len > 0) {
								if (copy_from_user(output + size, compat_ptr(ptr), len)) {
									err = true;
									break;
								}
								size += len;
							}
						}
						output[size++] = '\0';
						if (!err){
							output_scdata(output, size, i, test_id, no+1);
						}
						if (output) {
							kfree(output);
							output = NULL;
						}
					}
					break;
				}
				case ARG_FDPAIR: {
					int fd[2];
					if (copy_from_user(fd, compat_ptr((compat_uptr_t) arg), sizeof(fd)) != 0) {
						fd[0] = -1;
						fd[1] = -1;
					}
					output_scdata(fd, sizeof(fd), i, test_id, no);
				}
				default:
					break;
				}
				
			}
		}
	}
	else {
		if (no <= 280 && no > 0){
			// process specific parameters
			for (i = 0; i <= 6; ++i) {
				u64 arg = i == 6 ? regs->regs[0] : (i == 0 ? regs->orig_x0 : regs->regs[i]);
				switch(compat64_syscall_arg_type[no][i]) {
				case ARG_FD: {
					output_scinfo(regs, pid, test_id, call_pos);
					break;
				}
				case ARG_PATH: {					
					char *path = NULL;
					int path_len;
					path = kmalloc(PATH_MAX, GFP_KERNEL);
					if (unlikely(!path)) {
						pr_warn("syscall_test: %d: [%d] kmalloc failed\n", pid, test_id);
					} 
					else {
						if (access_ok(VERIFY_READ, (void __user *) arg, PATH_MAX - 1)){
							path_len = strncpy_from_user(path, (void __user *) arg, PATH_MAX - 1);
							if (likely(path_len > 0)) {
								path[path_len] = '\0';
								output_scdata(path, path_len + 1, i, test_id, no);
							}
						}
						else{
							pr_warn("syscall_test: error address: %p\n", (void __user *) arg);
						}
					}
					if (path) {
						kfree(path);
						path = NULL;
					}
					break;
				}
				case ARG_ARGV: {
					void __user * argv = (void __user *) arg;
					char *output = kmalloc(4096, GFP_KERNEL);
					int size = 0;
					bool err = false;

					if (unlikely(!output)) {
						pr_warn("syscall_test: %d: [%d] kmalloc failed\n", pid, test_id);
					} else {
						void __user * ptr;
						for ( ; ; ++argv) {
							int len;
							if (copy_from_user(&ptr, argv, sizeof(ptr))) {
								err = true;
								break;
							}
							if (!ptr)
								break;
							len = strnlen_user(ptr, MAX_ARG_STRLEN);
							if (len > MAX_ARG_STRLEN) {
								err = true;
								break;
							}
							--len;
							if (len <= 0)
								continue;
							if (size > 0 && size < 4095)
								output[size++] = ' ';
							if (len > 4095 - size)
								len = 4095 - size;
							if (len > 0) {
								if (copy_from_user(output + size, ptr, len)) {
									err = true;
									break;
								}
								size += len;
							}
						}
						output[size++] = '\0';
						if (!err){
							output_scdata(output, size, i, test_id, no+1);
						}
						if (output) {
							kfree(output);
							output = NULL;
						}
					}
					break;
				}
				case ARG_FDPAIR: {
					int fd[2];
					if (copy_from_user(fd, (void __user *) arg, sizeof(fd)) != 0) {
						fd[0] = -1;
						fd[1] = -1;
					}
					output_scdata(fd, sizeof(fd), i, test_id, no);
				}
				default:
					break;
				}
			}
		}
	}
}

// 1
extern void test_syscall_exit(struct pt_regs *regs)
{
	test_syscall_log(regs, 1);
}

// 1
extern void test_syscall_enter(struct pt_regs *regs)
{
	if (test_thread_flag(TIF_32BIT)) {
		switch (regs->syscallno) {
		case NR_compat_exit:
		case NR_compat_exit_group:
		case NR_compat_sched_yield:
		case NR_compat_execve:
		case NR_compat_connect:
			test_syscall_log(regs, 0);
		}
	} else {
		switch (regs->syscallno) {
		case NR64_compat_exit:
		case NR64_compat_exit_group:
		case NR64_compat_sched_yield:
		case NR64_compat_execve:
		case NR64_compat_connect:
			test_syscall_log(regs, 0);
		}
	}
}

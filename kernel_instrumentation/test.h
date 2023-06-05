// include/linux/test.h
#ifndef _LINUX_TEST_H
#define _LINUX_TEST_H

struct pt_regs;

extern void test_syscall_enter(struct pt_regs *);
extern void test_syscall_exit(struct pt_regs *);

#endif

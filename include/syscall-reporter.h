/*
 * syscall reporting example for seccomp
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Kees Cook <keescook@chromium.org>
 *  Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose, and can serve as a
 * starting point for developing applications using mode 2 seccomp.
 */
#ifndef _BPF_REPORTER_H_
#define _BPF_REPORTER_H_

#include "seccomp-bpf.h"

/* This redefines "KILL_PROCESS" into a TRAP for the reporter hook.
 * Only included under #ifdef DEBUG_SECCOMP — never in production builds.
 */
#undef KILL_PROCESS
#define KILL_PROCESS \
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)

extern int install_syscall_reporter(void);

#endif

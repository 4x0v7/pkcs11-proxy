/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-daemon-standalone.c - A sample daemon.

   Copyright (C) 2008, Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "pkcs11/pkcs11.h"

#include "gck-rpc-layer.h"
#include "gck-rpc-tls.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <dlfcn.h>
#include <pthread.h>

#include <syslog.h>

#ifdef __MINGW32__
# include <winsock2.h>
#endif

#define SOCKET_PATH "tcp://127.0.0.1"

#ifdef SECCOMP
#include <seccomp.h>
//#include "seccomp-bpf.h"
#ifdef DEBUG_SECCOMP
# include "syscall-reporter.h"
#endif /* DEBUG_SECCOMP */
#include <fcntl.h> /* for seccomp init */
#endif /* SECCOMP */


static int install_syscall_filter(const int sock, const char *path)
{
	(void)sock;
	(void)path;
#ifdef SECCOMP
	int rc = -1;
	scmp_filter_ctx ctx;

#ifdef DEBUG_SECCOMP
	ctx = seccomp_init(SCMP_ACT_TRAP);
#else
	ctx = seccomp_init(SCMP_ACT_KILL);
#endif /* DEBUG_SECCOMP */
	if (ctx == NULL)
		goto failure_scmp;
	/*
	 * These are the basic syscalls needed to be able to use
	 * the syscall-reporter to figure out the rest
	 */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
#ifdef DEBUG_SECCOMP
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
# ifdef __NR_sigreturn
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
# endif
#endif /* DEBUG_SECCOMP */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	/*
	 * Network related syscalls.
	 */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);
	if (sock) {
		/* Allow accept() only for the listening socket */
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(accept), 1,
				 SCMP_A0(SCMP_CMP_EQ, sock));
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(accept4), 1,
				 SCMP_A0(SCMP_CMP_EQ, sock));
	}
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
	if (path[0] &&
	    (strncmp(path, "tcp://", strlen("tcp://")) == 0 ||
	     strncmp(path, "tls://", strlen("tls://")) == 0)) {
		/* TCP/TLS socket */
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
		/*
		 * OpenSSL 3.x attempts kTLS via setsockopt(TCP_ULP).
		 * getnameinfo may probe NSS via socket/connect.
		 */
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
	}

	/*
	 * pthreads and memory management.
	 */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
#ifdef __NR_clone3
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(clone3), 0);
#endif
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(munlock), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
#ifdef __NR_rseq
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);
#endif

	/*
	 * pthreads reads /sys/devices/system/cpu/online at startup.
	 * Certs are loaded before seccomp, so no TLS file I/O needed here.
	 */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			 SCMP_A1(SCMP_CMP_EQ, O_RDONLY | O_CLOEXEC));
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);

	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

	/*
	 * TLS 1.3 requires getrandom() for key material.
	 */
	if (path[0] &&
	    strncmp(path, "tls://", strlen("tls://")) == 0) {
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
	}

	/*
	 * UNIX domain socket
	 */
	if (path[0] &&
	    strncmp(path, "tcp://", strlen("tcp://")) != 0 &&
	    strncmp(path, "tls://", strlen("tls://")) != 0) {
		seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
	}

	/*
	 * Allow spawned threads to initialize a new seccomp policy (subset of this).
	 */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0);

	/*
	 * Signal handling and process management.
	 */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);

	/*
	 * SoftHSM 1.3.0 required syscalls
	 */
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

#ifdef DEBUG_SECCOMP
	/* Dumps the generated BPF rules in sort-of human readable syntax. */
	seccomp_export_pfc(ctx,STDERR_FILENO);

	/* Print the name of syscalls stopped by seccomp. Should not be used in production. */
        if (install_syscall_reporter())
                return 1;
#endif /* DEBUG_SECCOMP */

	rc = seccomp_load(ctx);
	if (rc < 0)
		goto failure_scmp;
	seccomp_release(ctx);

	return 0;

failure_scmp:
	errno = -rc;
	fprintf(stderr, "Seccomp filter initialization failed, errno = %u\n", errno);
	return errno;
#else /* SECCOMP */
        return 0;
#endif /* SECCOMP */
}


#if 0
/* Sample configuration for loading NSS remotely */
static CK_C_INITIALIZE_ARGS p11_init_args = {
	NULL,
	NULL,
	NULL,
	NULL,
	CKF_OS_LOCKING_OK,
	"init-string = configdir='/tmp' certPrefix='' keyPrefix='' secmod='/tmp/secmod.db' flags="
};
#endif

static int is_running = 1;

static int usage(void)
{
	fprintf(stderr, "usage: pkcs11-daemon pkcs11-module [<socket>|\"-\"]\n\tUsing \"-\" results in a single-thread inetd-type daemon\n");
	exit(2);
}

void termination_handler (int signum)
{
	(void)signum;
	is_running = 0;
}

enum {
	/* Used to un-confuse clang checker */
	GCP_RPC_DAEMON_MODE_INETD = 0,
	GCP_RPC_DAEMON_MODE_SOCKET
};

int main(int argc, char *argv[])
{
	CK_C_GetFunctionList func_get_list;
	CK_FUNCTION_LIST_PTR funcs;
	void *module;
	const char *path;
	fd_set read_fds;
	int sock, ret, mode;
	CK_RV rv;
	CK_C_INITIALIZE_ARGS init_args;
	GckRpcTlsState *tls;

	/* The module to load is the argument */
	if (argc != 2 && argc != 3)
		usage();

        openlog("pkcs11-proxy",LOG_CONS|LOG_PID,LOG_DAEMON);

	fprintf(stderr, "pkcs11-proxy starting\n");

	/* Load the library */
	module = dlopen(argv[1], RTLD_NOW);
	if (!module) {
		fprintf(stderr, "couldn't open library: %s: %s\n", argv[1],
			dlerror());
		exit(1);
	}
	fprintf(stderr, "  module: %s\n", argv[1]);

	/* Lookup the appropriate function in library */
	func_get_list =
	    (CK_C_GetFunctionList) dlsym(module, "C_GetFunctionList");
	if (!func_get_list) {
		fprintf(stderr,
			"couldn't find C_GetFunctionList in library: %s: %s\n",
			argv[1], dlerror());
		exit(1);
	}

	/* Get the function list */
	rv = (func_get_list) (&funcs);
	if (rv != CKR_OK || !funcs) {
		fprintf(stderr,
			"couldn't get function list from C_GetFunctionList"
			"in libary: %s: 0x%08x\n",
			argv[1], (int)rv);
		exit(1);
	}

	/* RPC layer expects initialized module */
	memset(&init_args, 0, sizeof(init_args));
	init_args.flags = CKF_OS_LOCKING_OK;

	rv = (funcs->C_Initialize) (&init_args);
	if (rv != CKR_OK) {
		fprintf(stderr, "couldn't initialize module: %s: 0x%08x\n",
			argv[1], (int)rv);
		exit(1);
	}
	fprintf(stderr, "  pkcs11: module initialized\n");

	path = getenv("PKCS11_DAEMON_SOCKET");
	if (!path && argc == 3)
           path = argv[2];
        if (!path)
	   path = SOCKET_PATH;

	/* Initialize TLS, if appropriate */
	tls = NULL;
	if (! strncmp("tls://", path, 6)) {
		tls = calloc(1, sizeof(GckRpcTlsState));
		if (tls == NULL) {
			fprintf(stderr, "can't allocate memory for TLS\n");
			exit(1);
		}

		if (! gck_rpc_init_tls(tls, GCK_RPC_TLS_SERVER)) {
			fprintf(stderr, "TLS initialization failed\n");
			exit(1);
		}
		fprintf(stderr, "  tls:    TLS 1.3 server initialized (mTLS=%s)\n",
			getenv("PKCS11_PROXY_TLS_REQUIRE_MTLS") &&
			strcmp(getenv("PKCS11_PROXY_TLS_REQUIRE_MTLS"), "true") == 0
			? "required" : "off");
	}

	if (strcmp(path,"-") == 0) {
		/* inetd mode */
		sock = 0;
		mode = GCP_RPC_DAEMON_MODE_INETD;
	} else {
		/* Do some initialization before enabling seccomp. */
		sock = gck_rpc_layer_initialize(path, funcs);
		if (sock == -1)
			exit(1);

		/* Shut down gracefully on SIGTERM. */
		if (signal (SIGTERM, termination_handler) == SIG_IGN)
			signal (SIGTERM, SIG_IGN);

		mode = GCP_RPC_DAEMON_MODE_SOCKET;
	}

	fprintf(stderr, "  listen: %s\n", path);
	fprintf(stderr, "pkcs11-proxy ready\n");

	/*
	 * Enable seccomp. This is essentially a whitelist containing all the syscalls
	 * we expect to call from here on. Anything not whitelisted will cause the
	 * process to terminate.
	 */
        if (install_syscall_filter(sock, path))
        	return 1;

        if (mode == GCP_RPC_DAEMON_MODE_INETD) {
           gck_rpc_layer_inetd(funcs);
        } else if (mode == GCP_RPC_DAEMON_MODE_SOCKET) {
	   is_running = 1;
	   while (is_running) {
		FD_ZERO(&read_fds);
		FD_SET(sock, &read_fds);
		ret = select(sock + 1, &read_fds, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "error watching socket: %s\n",
				strerror(errno));
			exit(1);
		}

		if (FD_ISSET(sock, &read_fds))
			gck_rpc_layer_accept(tls);
	   }

	   gck_rpc_layer_uninitialize();
        } else {
		/* Not reached */
		exit(-1);
	}

	rv = (funcs->C_Finalize) (NULL);
	if (rv != CKR_OK)
		fprintf(stderr, "couldn't finalize module: %s: 0x%08x\n",
			argv[1], (int)rv);

	dlclose(module);

	if (tls) {
		gck_rpc_close_tls(tls);
		free(tls);
		tls = NULL;
	}

	return 0;
}

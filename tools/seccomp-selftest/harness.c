/* Faithful default-deny seccomp test harness.
 * Installs a BPF filter (default ERRNO EPERM) allowing only allowed_nr[],
 * exactly as Docker would compile a defaultAction=ERRNO allowlist profile,
 * then execve()s the target. Proves (a) sufficiency: target runs; and used
 * with a denied syscall, (b) denial: target gets EPERM.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include "allowed.h"
#define offsetof_nr 0
#define offsetof_arch 4

int main(int argc, char **argv){
  if(argc<2){ fprintf(stderr,"usage: %s cmd args...\n",argv[0]); return 2; }
  /* Build: validate arch, load nr, JEQ each allowed -> ALLOW, else ERRNO(EPERM). */
  int n = allowed_count;
  int len = 3 /*arch check(2)+load nr(1)*/ + n /*one JEQ per allowed*/ + 2 /*errno,allow*/;
  struct sock_filter *f = calloc(len, sizeof(*f));
  int i=0;
  /* load arch */
  f[i++] = (struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof_arch);
  /* if arch != X86_64 -> ERRNO (kill-ish); jump to errno insn */
  /* we compute jump targets after we know indices; use placeholders then patch */
  int arch_jne_idx=i;
  f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 0, 0); /* patch jf */
  /* load nr */
  f[i++] = (struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof_nr);
  int first_jeq=i;
  for(int k=0;k<n;k++){
    /* if nr==allowed -> jump to ALLOW (computed later): set jt as distance to allow insn */
    f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, allowed_nr[k], 0, 0);
  }
  int errno_idx=i;
  f[i++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  int allow_idx=i;
  f[i++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW);
  /* patch arch check: if not X86_64 jump to errno_idx */
  f[arch_jne_idx].jf = (errno_idx - arch_jne_idx - 1);
  f[arch_jne_idx].jt = 0; /* equal falls through to load nr */
  /* patch each JEQ: jt = distance to allow_idx */
  for(int k=0;k<n;k++){
    int idx = first_jeq + k;
    f[idx].jt = (allow_idx - idx - 1);
    f[idx].jf = 0; /* next check */
  }
  struct sock_fprog prog = { .len=(unsigned short)len, .filter=f };
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){ perror("no_new_privs"); return 3; }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)){ perror("set_seccomp"); return 3; }
  execvp(argv[1], &argv[1]);
  perror("execvp"); return 127;
}

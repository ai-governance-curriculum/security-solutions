# SOLUTION — Exercise 02: Seccomp + AppArmor Profiles

> Read this *after* attempting the exercise. The profiles below illustrate the
> shape of a defensible answer; a real production profile must be regenerated
> against the exact image and dependency versions you ship.

---

## 1. Solution overview

Seccomp and AppArmor are complementary kernel-level controls layered *under*
Pod Security Standards. They reduce the post-compromise blast radius: even if
an attacker gets code execution inside the model-serving container, they hit
a syscall wall (seccomp) and a file/network/capability wall (AppArmor) before
they can read every file, mount things, ptrace neighbours, or exfiltrate.

The order of operations matters:

1. **Apply `RuntimeDefault` seccomp namespace-wide.** This blocks roughly the
   same ~50 syscalls Docker has blocked by default for a decade. Anything that
   trips this is almost certainly already broken by Restricted PSS.
2. **Profile the workload** with a tracer (Inspektor Gadget seccomp advisor or
   `syscall2seccomp`) under realistic load.
3. **Author a stricter custom seccomp profile** that trims the long tail of
   syscalls Python + PyTorch + Uvicorn never use.
4. **Layer AppArmor** for things seccomp can't easily express: filesystem
   path restrictions, capability scoping, network address scoping.
5. **Roll out `complain` → `enforce`** for AppArmor, watching DENIED events,
   the same staged pattern PSS uses.

The numbers in this solution (allowed-syscall count, profile sizes) are
illustrative ranges, not measurements from a specific build — the exact set
depends on glibc/musl, Python version, PyTorch CUDA build, and whether the
serving stack uses gunicorn vs. uvicorn workers. Always re-profile against
the image you actually ship.

## 2. Worked answer / implementation

### Part 1 — Seccomp

#### 2.1 RuntimeDefault rollout

**Scope:** every pod in `recs` and `fraud` (and ideally every namespace
running a Restricted PSS profile — Restricted requires a non-`Unconfined`
seccomp profile).

**Pod-spec snippet** to merge into Helm chart values or the workload manifest:

```yaml
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: model-serving
      securityContext:
        # belt-and-suspenders: per-container overrides win, so set both.
        seccompProfile:
          type: RuntimeDefault
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        capabilities:
          drop: ["ALL"]
```

**Acceptance test** (run against staging):

```bash
# Pod is admitted under Restricted PSS — i.e., seccompProfile is set
kubectl -n recs get pod recs-serving-0 -o jsonpath='{.spec.securityContext.seccompProfile.type}'
# expect: RuntimeDefault

# Workload survives a realistic load test for ≥30 minutes with no
# audit-log entries pointing at SECCOMP. RuntimeDefault denials show up as
# EPERM in containerd events; run for the cohort of typical request shapes.
```

If the workload fails with `Operation not permitted` from a syscall the
RuntimeDefault profile blocks, the right answer is almost always to fix the
caller (drop the dependency, change the launch flag) before reaching for a
custom profile.

#### 2.2 Custom profile — generation methodology

Tooling:

- **Inspektor Gadget — `trace_seccomp` / advise seccomp-profile**: runs an
  eBPF tracer that observes the pod's actual syscalls and emits a profile.
- **`syscall2seccomp`** (Falco project): another syscall observer + profile
  generator.
- **`strace -ff -c` against the container's PID 1**: low-tech fallback that
  gives a syscall histogram; useful for sanity-checking the tracer output.

Methodology, written so anyone can re-run it:

1. **Boot the workload with `seccompProfile.type: Unconfined`** in a
   sandboxed namespace. Only do this in staging.
2. **Run a representative load**: the regression suite, a 30-minute
   production traffic replay, model warm-up, a graceful shutdown. Cold paths
   missed here become alerts later — that's the design trade.
3. **Capture syscalls** for the entire window using one tracer. Don't union
   two tracers' outputs without diffing them; they sometimes disagree on
   indirect calls like `clone3` vs. `clone`.
4. **Generate a draft profile** in `SCMP_ACT_ERRNO` mode for everything not
   observed, `SCMP_ACT_ALLOW` for everything observed.
5. **Add safety syscalls** that always need to work (signal handlers,
   shutdown): `rt_sigreturn`, `exit`, `exit_group`, `tgkill`, plus the
   architecture-specific syscalls the tracer can miss because they happen
   before tracing attaches (`execve` of PID 1 itself).
6. **Run the profile in audit mode** (`SCMP_ACT_LOG` for the deny set) and
   replay traffic for another window. Promote to `ERRNO` once the audit log
   is clean for 24 h.

**Profile JSON** (illustrative — regenerate per image build):

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "access", "arch_prctl", "bind", "brk", "close",
        "connect", "dup", "dup2", "dup3", "epoll_create1", "epoll_ctl",
        "epoll_pwait", "epoll_wait", "eventfd2", "execve", "exit",
        "exit_group", "fcntl", "fstat", "fstatfs", "futex", "getcwd",
        "getdents64", "getegid", "geteuid", "getgid", "getpid", "getppid",
        "getrandom", "getrlimit", "getsockname", "getsockopt", "gettid",
        "gettimeofday", "getuid", "ioctl", "kill", "listen", "lseek",
        "madvise", "mmap", "mprotect", "mremap", "munmap", "nanosleep",
        "newfstatat", "open", "openat", "pipe", "pipe2", "poll", "ppoll",
        "prctl", "pread64", "pwrite64", "read", "readlink", "readlinkat",
        "readv", "recvfrom", "recvmsg", "rseq", "rt_sigaction",
        "rt_sigprocmask", "rt_sigreturn", "sched_getaffinity",
        "sched_yield", "select", "sendmsg", "sendto", "set_robust_list",
        "set_tid_address", "setsockopt", "shutdown", "sigaltstack",
        "socket", "socketpair", "stat", "statfs", "tgkill", "uname",
        "wait4", "waitid", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["clone", "clone3"],
      "action": "SCMP_ACT_ALLOW",
      "args": [
        {
          "index": 0,
          "value": 2114060288,
          "op": "SCMP_CMP_MASKED_EQ",
          "valueTwo": 0
        }
      ],
      "comment": "Allow only thread-creation flags (no new namespaces)."
    }
  ]
}
```

**Deploy** the profile by placing the JSON at
`/var/lib/kubelet/seccomp/profiles/model-serving.json` on every node (via a
DaemonSet, or via the Security Profiles Operator), and reference it from
the pod spec:

```yaml
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/model-serving.json
```

**Test scenarios** (each one is a separate replay):

1. Cold start: pull weights, load model, warm caches, accept first request.
2. Sustained load: representative RPS for 30 minutes.
3. Long-tail request shape: largest expected request body.
4. Graceful shutdown: `SIGTERM` followed by `SIGKILL` after grace period.
5. Crash recovery: kill -9 the worker; supervisor restarts it.
6. Health endpoints under load.

A passing run produces zero new entries in the audit log; a failing run
produces an `EPERM` traced back to a real workload code path. *Add the
syscall back, do not switch the profile off.*

**Acceptance criteria:**

- Profile is `SCMP_ACT_ERRNO` (default-deny), not `SCMP_ACT_LOG`.
- Allow-list is < 100 syscalls. (Above ~120 you're approximating
  `RuntimeDefault`; below ~60 you've probably missed a code path.)
- All six test scenarios pass with zero violations.
- The profile JSON is checked into the same repo as the workload chart, so
  bumping the image and updating the profile happens in one PR.

**Rollback:** revert the `localhostProfile` reference to
`seccompProfile.type: RuntimeDefault`. Pods restart and the previous,
weaker-but-known-good profile is in effect.

#### 2.3 Risk: profile drift on dependency upgrade

A `pip install --upgrade torch` can introduce a new syscall (a CUDA driver
upgrade, a new gRPC transport, a new tokenizer that uses `mlock`). Without
detection, the production pod crashes on its first request post-deploy.

**Detection:**

- CI step: rebuild the image, run the test scenarios from §2.2 against the
  *current production seccomp profile*, fail the build if any syscall is
  blocked.
- Canary: route 1% of traffic to the new image+profile pair, watch for
  `EPERM` in container logs for ≥ 1 hour before promoting.

**Mitigation when detection fires:**

- The CI failure shows the *exact* missing syscall. Add it to the profile,
  re-run the suite, ship both image and profile in one PR. Never ship the
  new image with the old profile.

### Part 2 — AppArmor

#### 2.4 Profile design (rationale per restriction)

| Restriction | Why | What it blocks |
|---|---|---|
| Read-only access to `/models` | The serving container loads weights, never writes them. Writes to `/models` are the canonical model-poisoning signal. | Tampered weights from inside the pod (still detected by file-integrity monitoring, but with this rule the syscall is denied outright). |
| Read+write `/tmp` and the pod's writable layer | Python writes pyc bytecode, model framework writes cache files. Forbidding these breaks startup. | Nothing — this is permissive on purpose; the rest of the FS is read-only. |
| Bind one TCP port (the serving port) | Defence-in-depth against an attacker reusing the pod as an exfil bouncer or opening a second listener. | Reverse-shell / bind-shell on a non-standard port. |
| Outbound only to defined destinations | Egress allow-list at the AppArmor layer in addition to NetworkPolicy. Belt + suspenders because NetworkPolicy is enforced at L3/L4 by the CNI; AppArmor is enforced in-kernel by LSM. | Egress to attacker C2 if the CNI is bypassed or misconfigured. |
| Deny `mount`, `pivot_root`, `umount` | None of these are used by a serving pod. They are container-escape primitives. | Container-escape attempts that need to manipulate mount namespaces. |
| Deny `ptrace` | Serving pod has no business attaching to other processes. | Lateral inspection of a sidecar (e.g., reading mTLS secrets from envoy). |
| Deny `unshare`, `setns` (capability + syscall pair) | Same as above — escape primitives. | New-namespace creation that's part of the standard escape chain. |
| Deny all capabilities (`deny capability *`) | The pod-spec already drops all caps; this is the AppArmor-layer mirror so a misconfigured pod can't silently regain them. | A pod manifest re-adding `NET_ADMIN`. |

#### 2.5 Profile text

```
#include <tunables/global>

profile model-serving flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/openssl>

  # ---- Filesystem ----
  /models/** r,
  deny /models/** w,

  /tmp/** rw,
  /var/tmp/** rw,
  /proc/sys/kernel/random/uuid r,
  /proc/self/** r,
  /sys/fs/cgroup/** r,

  # Python + app
  /usr/lib/python3/** r,
  /usr/local/lib/python3.*/** r,
  /opt/app/** r,
  /opt/app/cache/** rw,

  # Block the rest of /etc beyond the dynamic-loader basics
  /etc/ld.so.cache r,
  /etc/ssl/certs/** r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/hostname r,
  /etc/nsswitch.conf r,
  deny /etc/shadow rwklx,
  deny /etc/passwd w,
  deny /etc/group w,

  # ---- Networking ----
  network inet stream,
  network inet6 stream,
  network inet dgram,    # DNS
  network inet6 dgram,

  # AppArmor cannot express "only port 8080" — that lives in NetworkPolicy.
  # The complementary AppArmor rule is to deny raw sockets.
  deny network packet,
  deny network raw,

  # ---- Capabilities ----
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_chroot,
  deny capability dac_override,
  deny capability dac_read_search,
  deny capability net_admin,
  deny capability net_raw,
  deny capability setuid,
  deny capability setgid,

  # ---- Mount / namespace ops ----
  deny mount,
  deny umount,
  deny pivot_root,
  deny remount,

  # ---- Process introspection ----
  deny ptrace,
  deny @{PROC}/[0-9]*/mem rwklx,
  deny @{PROC}/[0-9]*/maps r,
  deny @{PROC}/kcore rwklx,
  deny @{PROC}/kallsyms r,
}
```

Note: AppArmor's `network` rules express L3/L4 socket families. **Per-port
or per-IP egress allow-listing is the job of NetworkPolicy or the service
mesh, not AppArmor.** Stating that misunderstanding up front is part of the
rationale.

#### 2.6 Deployment

1. **Distribute the profile to every node.** A DaemonSet running a privileged
   init container that writes the profile to `/etc/apparmor.d/model-serving`
   and runs `apparmor_parser -r /etc/apparmor.d/model-serving`. The Security
   Profiles Operator does this declaratively.
2. **Annotate the pod** (legacy syntax pre-1.30) or use the
   `securityContext.appArmorProfile` field (1.30+):

   ```yaml
   # Kubernetes 1.30+: native field
   spec:
     securityContext:
       appArmorProfile:
         type: Localhost
         localhostProfile: model-serving
     containers:
       - name: model-serving
         securityContext:
           appArmorProfile:
             type: Localhost
             localhostProfile: model-serving

   # Legacy annotation (still works in 1.30, removed in a future release)
   metadata:
     annotations:
       container.apparmor.security.beta.kubernetes.io/model-serving: localhost/model-serving
   ```

3. **`complain` → `enforce` transition.**
   - Week 1: load the profile in `complain` mode (`apparmor_parser -C`).
     Watch `dmesg` / kernel audit log for `apparmor="ALLOWED"` lines that
     would have been DENIED. Each is a profile gap.
   - Week 2: tighten the profile based on what `complain` surfaced, re-load
     in `complain` for a second confirmation window.
   - Week 3: switch to `enforce`. Continue watching `apparmor="DENIED"` in
     the host audit log; expect zero entries for the steady state.

#### 2.7 Operational concerns

- **Where violations surface.** AppArmor writes to the kernel audit
  subsystem (`/var/log/audit/audit.log` on systemd hosts, or `dmesg` if
  auditd isn't running). Falco's `apparmor_violation` rule (or a Fluent Bit
  parser on the audit log) lifts these into the SIEM.
- **Triage path.**
  1. Identify the pod from the audit-log `name=...` field (the AppArmor
     profile name is the same as the workload).
  2. Pull the container's process tree at incident time
     (`kubectl debug node/<n> -it --image=busybox`).
  3. Decide whether the DENIED operation is benign-but-new (legitimate code
     path the profile missed → update profile, ship in next release) or
     malicious (e.g., a child process trying `mount` → page on-call, treat
     as the §Exercise-05 runbook).
- **Profile review cadence.** Re-generate the seccomp profile and re-check
  AppArmor coverage on every minor framework upgrade (PyTorch, Triton, vLLM).
  Tie this to the same release gate as image-vulnerability scans.

### 2.8 Comparison: seccomp alone vs. seccomp + AppArmor

| Question | Answer |
|---|---|
| Custom seccomp alone is enough when … | … the workload's threat model is dominated by syscall-level escape primitives (BPF, perf_event_open, keyctl) and you have strong filesystem + network containment from other layers (read-only root FS via PSS Restricted, default-deny NetworkPolicy, mTLS mesh). |
| AppArmor adds clear value when … | … you need *path-aware* restrictions ("read-only /models") that seccomp can't express, or you need a second LSM layer behind seccomp for defence-in-depth against syscall-filter bypasses, or your distro ships AppArmor by default (Ubuntu nodes) so the cost is low. |
| Use SELinux instead when … | … your platform standardises on RHEL/CoreOS where SELinux is the native LSM. The same arguments apply; the implementation language differs. AppArmor and SELinux do not coexist on the same node. |

## 3. Validation steps

1. **Lint the seccomp JSON** with `jq` and against the OCI runtime spec
   schema; runtimes will refuse a malformed profile silently in some setups.
2. **Lint the AppArmor profile** with `apparmor_parser -Q` (dry parse).
3. **Stage replay (Part 1 + Part 2 together).** Apply both profiles to a
   staging pod, run the six test scenarios from §2.2, confirm:
   - Pod is Ready.
   - Health/readiness pass for 30 min.
   - Zero `EPERM`s in container logs.
   - Zero `apparmor="DENIED"` in host audit log.
4. **Negative tests (this is the important one).** From inside the pod (use
   `kubectl debug`), attempt each action and confirm denial:
   - `cat /etc/shadow` → permission denied.
   - `mount -t tmpfs none /mnt` → operation not permitted.
   - `nc -l -p 9999` → operation not permitted.
   - `nsenter -t 1 -m -u -i -n -p` → operation not permitted.
   - `python -c "import ctypes; ctypes.CDLL('libc.so.6').ptrace(0,0,0,0)"` →
     denied.
   - Write to `/models/test.bin` → denied.
   Each denial proves a different rule is wired.
5. **Negative-test CI gate.** The above commands run as a `Job` in the
   staging cluster on every chart release. If any returns success, the
   release blocks.

## 4. Rubric / review checklist

- [ ] **RuntimeDefault** is applied namespace-wide (in pod template defaults
      or via a Kyverno mutating policy), not per-pod.
- [ ] **Custom seccomp profile** uses `SCMP_ACT_ERRNO` as default and lists
      ≤ ~100 allowed syscalls.
- [ ] **Profile generation method** names a tool (Inspektor Gadget,
      `syscall2seccomp`, etc.) and a replay workload, not "we observed
      production."
- [ ] **At least six test scenarios** include cold start, sustained load,
      graceful shutdown, crash recovery.
- [ ] **AppArmor profile** restricts filesystem (`/models` ro), network
      (deny raw + packet sockets), capabilities (deny `sys_admin`, `ptrace`,
      `net_admin`), and mount/namespace ops.
- [ ] **`complain` → `enforce`** is a named, multi-week sequence with a
      reading of the kernel audit log between stages.
- [ ] **Violations have a routing path** (audit-log → SIEM / Falco) and a
      triage rubric (benign-but-new vs. malicious).
- [ ] **Drift detection** is described for both layers (CI seccomp replay on
      image build; profile-regeneration cadence).
- [ ] **Negative tests** are runnable and listed.
- [ ] **Comparison section** is honest about when AppArmor adds value vs.
      when seccomp alone is enough.

## 5. Common mistakes

- **Skipping RuntimeDefault and jumping to a custom profile.** The custom
  profile is harder to reason about than RuntimeDefault; the team should be
  using RuntimeDefault for everything by default and reserving custom
  profiles for the small set of workloads where the marginal hardening is
  worth the maintenance.
- **Generating the profile by tracing production traffic only.** The
  tracer misses cold-path syscalls — graceful shutdown, crash recovery, the
  first request after weight reload. The profile then blocks them in
  production. Always include cold paths in the replay.
- **Setting the seccomp default action to `SCMP_ACT_LOG` "for safety".** Log
  is observe-only — it does not block. A profile in log mode adds zero
  defence; it only adds noise. Use log mode as a temporary stage on the way
  to errno, then switch.
- **Forgetting that AppArmor can't express port-level network rules.**
  Writing `network tcp port 8080` is a profile syntax error. Per-port egress
  belongs in NetworkPolicy.
- **Mixing AppArmor and SELinux on the same node.** Pick one based on the
  distro. Trying to run both produces undefined behaviour.
- **Custom seccomp profile that's looser than RuntimeDefault** because the
  generator wasn't run against a denial-by-default base. Always diff the
  generated profile against RuntimeDefault; if the custom one allows
  syscalls RuntimeDefault blocks, that is the bug.
- **Profile lives in a separate repo from the workload.** Then a dependency
  upgrade lands without the profile change, breaks the canary, and the team
  blames "AppArmor". Co-locate them.

## 6. References

- Kubernetes Seccomp tutorial — `RuntimeDefault`, `Localhost`, profile
  layout.
  <https://kubernetes.io/docs/tutorials/security/seccomp/>
- Kubernetes AppArmor tutorial — profile distribution, annotation syntax,
  the 1.30+ `appArmorProfile` field.
  <https://kubernetes.io/docs/tutorials/security/apparmor/>
- Security Profiles Operator — managing seccomp + AppArmor + SELinux as
  Kubernetes CRDs.
  <https://github.com/kubernetes-sigs/security-profiles-operator>
- Inspektor Gadget — eBPF-based syscall tracing for profile generation.
  <https://github.com/inspektor-gadget/inspektor-gadget>
- AppArmor project — profile syntax reference.
  <https://gitlab.com/apparmor/apparmor/-/wikis/QuickProfileLanguage>
- NSA / CISA Kubernetes Hardening Guide v1.2 — seccomp + AppArmor as the
  named pod-hardening layers.
  <https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF>
- NIST SP 800-190 §4.4 — kernel-mediated container isolation.
  <https://csrc.nist.gov/pubs/sp/800/190/final>
- MITRE ATT&CK for Containers — T1611 (escape to host), the technique class
  these profiles target.
  <https://attack.mitre.org/matrices/enterprise/containers/>
- Module 08 lecture notes §3–§4 (Seccomp, AppArmor) for the SmartRecs
  framing.

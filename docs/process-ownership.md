# Owned process groups: W3.2b1 internal boundary

Implemented 8 September 2026. Primary ADRL-OPS-001; secondary SAF-007, SEM-006, MEM-003
and TRU-001. This trusted local primitive has no public endpoint, CLI or journal bridge.
Only self-authored synthetic commands have been exercised. Schema 8 and API preview 4
are unchanged. The [attempt journal](attempt-lifecycle.md) still records intent alone.

## What it does

`ProcessOwner.run(ProcessSpec(...))` launches one explicitly supplied command with an
absolute executable path, expected executable SHA-256, absolute working directory and
explicit environment. It resolves and checks the executable, validates the request, and
passes one bounded request to a private Python launcher through private pipes. The
launcher checks the executable digest again before launching the command. This pins the
executable bytes at those checks; it does not pin scripts, modules, libraries or every
subsequent file read, or eliminate filesystem replacement races against a hostile account.

The launcher owns a fresh POSIX session/process group. It waits for the direct command,
reports its exit code, and stays alive until cleanup. The parent never polls or reaps this
launcher before its final group signal. A live or unreaped launcher reserves the PID used
for that signal. The parent sends one group SIGKILL, closes its control pipe and waits to
reap the launcher. It never signals that group after releasing the identity.

If the owner dies, control-pipe EOF makes the launcher kill its own group. A bounded
launcher watchdog also handles an owner that remains alive but stops monitoring. Workloads
inherit neither private control descriptors nor the parent's environment. The documented
defaults are `PATH=/usr/bin:/bin` and `LANG=C`; only the operator's explicit mapping is
added. A program may alter its own environment (Python can add locale settings). All three
standard streams are discarded; no raw command, environment, workspace path or output is
returned in a report. This does not hide arguments from operating-system process inspection.

## Limits and observations

`owned-process-policy-v1` defaults to 30 seconds of command runtime, 5 seconds for launch
and 2 seconds for reaping. Its upper bounds are 60, 10 and 5 seconds and 8,192 encoded launch
bytes. One instance admits one active run, one command launch and no retry. The private
wire protocol has a 10-second initial request bound and at most an 80-second watchdog;
the runner supplies a shorter watchdog from its recorded policy. Source hashes identify
both sides of this protocol. Process creation, executable hashing and operating-system
scheduling can outlast a configured timeout: these are bounded polling/wait policies,
not a hard real-time deadline.

An explicit stop returns a stopped observation after cleanup. Coroutine cancellation,
including repeated cancellation and event-loop shutdown, drains the protected executor
Future before propagating cancellation. A failed signal or unconfirmed reap prevents
reuse of that owner instance. The exact unreaped handle is retained without retrying a
signal from saved metadata. Signal failure may still be followed by successful launcher
self-cleanup on EOF; both observations stay visible rather than replacing the failure.

The in-memory `owned-process-report-v1` records a random run ID, direct-command outcome
and exit code, group-signal result, launcher reaping, elapsed time, full policy, a keyed
request reference, and executable/runner/launcher digests. It is not persisted in this
slice. A zero exit code is only the command's reported exit; it is not a quality label.
Reports always carry:

```text
containment = process_group_only
exact_close_eligible = false
eligible_for_learning = false
```

## Why this does not close a task

A child can detach into a new group/session. Another program, editor or prior task can
write the same folder. Sending SIGKILL and reaping the launcher also does not certify
completion of every descendant's kernel work. The tests deliberately demonstrate a
short-lived detached writer surviving group cleanup. Therefore this primitive cannot
establish an all-writer barrier, exact task-close attribution, workspace exclusivity or
a safe capture association. It is not a hostile-code sandbox, credential boundary or
protection against an attacker controlling the OS account.

The embedding process must keep normal SIGCHLD handling and have no competing child
reaper. Known non-default SIGCHLD settings are rejected before launch; arbitrary concurrent
reapers or later signal-handler changes are outside the trusted embedding contract.
The implementation backend is POSIX; actual test evidence is Python 3.12.7 on Darwin.
There is no Linux qualification or cross-harness claim from these tests.

W3.2b2 must qualify writer containment/admission, reserve terminal-record capacity and
coordinate erasure, release and restart before real supervised task execution. W3.2b3
must then bind the attempt and its reserved capture to that qualified close boundary.
Active plaintext leases and crash-leftover cleanup remain separate capture gates.
No native task payload, model call, routing change or learning authority follows from b1.

Evidence and disposition live in the sibling register's
[W3.2b1 report](../../adrl-world-class/reports/adrl-w3-2b1-process-ownership-2026-09-08.md).
The process fixtures are [test_process_owner.py](../tests/unit/test_process_owner.py).

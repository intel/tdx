.. SPDX-License-Identifier: GPL-2.0

Debugging loading the P-SEAMLDR and the TDX module
==================================================
boot-time trace
---------------
There are tracepoints to record SEAMCALL entry and exit.  (seam:seamcall_entry,
seam:seamcall_exit function events).  Enable ftrace and boot time tracing, and
update kernel command line to enable boot time tracepoint. An example kernel
command line looks like "trace_event=seam:*".  For details, please refer to
<fileDocumentation/trace/boottime-trace.rst>

After booting, the trace can be retrieved by
"cat /sys/kernel/debug/tracing/trace"::

        # tracer: nop
        #
        # entries-in-buffer/entries-written: 66450/66450   #P:224
        #
        #                                _-----=> irqs-off
        #                               / _----=> need-resched
        #                              | / _---=> hardirq/softirq
        #                              || / _--=> preempt-depth
        #                              ||| /     delay
        #           TASK-PID     CPU#  ||||   TIMESTAMP  FUNCTION
        #              | |         |   ||||      |         |
               swapper/0-1       [000] ...1    14.819509: seamcall_enter: op: SEAMLDR_INFO 1081185000 0 0 0 0 0
               swapper/0-1       [000] .N.1    14.847999: seamcall_exit: op: SEAMLDR_INFO err: TDX_SUCCESS(0) 1081185000 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
                  <idle>-0       [000] dN.2    85.565879: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                  <idle>-0       [000] dN.2    85.594079: seamcall_exit: op: SEAMLDR_INSTALL err: TDX_SUCCESS(0) 10a7c67000 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
                  <idle>-0       [001] dN.2    85.594088: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                  <idle>-0       [001] dN.2    85.622382: seamcall_exit: op: SEAMLDR_INSTALL err: TDX_SUCCESS(0) 10a7c67000 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
                  <idle>-0       [002] dN.2    85.622389: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                ...
                  <idle>-0       [223] dN.2    92.096809: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                  <idle>-0       [223] dN.2    92.140551: seamcall_exit: op: SEAMLDR_INSTALL err: TDX_SUCCESS(0) 10a7c67000 0 0 0 ffffffffb9e7ba7f fffffbfff73cf74f
               swapper/0-1       [019] .N.2    92.140556: seamcall_enter: op: TDH_SYS_INIT 0 0 0 0 0 0
               swapper/0-1       [019] .N.2    92.166347: seamcall_exit: op: TDH_SYS_INIT err: TDX_SUCCESS(0) 0 0 0 0 0 fffffbfff73cf74c
               swapper/0-1       [019] .N.2    92.166348: seamcall_enter: op: TDH_SYS_LP_INIT 0 0 0 0 0 0
               swapper/0-1       [019] .N.2    92.191947: seamcall_exit: op: TDH_SYS_LP_INIT err: TDX_SUCCESS(0) 0 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
               swapper/0-1       [019] .N.2    92.191948: seamcall_enter: op: TDH_SYS_INFO 133cd1000 400 133c9c400 20 0 0
               swapper/0-1       [019] .N.2    92.217539: seamcall_exit: op: TDH_SYS_INFO err: TDX_SUCCESS(0) 133cd1000 400 133c9c400 20 ffffffffb9e7ba67 fffffbfff73cf74c
               swapper/0-1       [031] d..2    92.344016: seamcall_enter: op: TDH_SYS_LP_INIT 0 0 0 0 0 0
                  <idle>-0       [006] d.h2    92.344018: seamcall_enter: op: TDH_SYS_LP_INIT 0 0 0 0 0 0

run-time trace
--------------
For run-time recording of trace event, there are several front end tool for
trace.  Record seam event (or seam:seamcall_entry or seam:seamcall_exit).  Here
is the example of trace-cmd::

  # record seam:* events. (both seamcall enter/exit events.)
  $ trace-cmd record -e seam
  <Ctrl^C>
  $ trace-cmd report

  # to record only seamcall enter event.
  $ trace-cmd record -e seam:seamcall_enter

  # to record only seamcall exit event.
  $ trace-cmd record -e seam:seamcall_exit

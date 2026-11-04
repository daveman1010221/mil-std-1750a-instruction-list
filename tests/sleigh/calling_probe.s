; Small functions whose decompiled result depends on the calling convention.
; tests/sleigh/VerifyCallingProbe.java checks what each one returns.

; A call must leave R15 where it was, so this reads back 7, not 5.
	global	probe_stack
probe_stack
	sisp	r15,2
	lisp	r0,5
	st	r0,0,r15
	lisp	r0,7
	st	r0,1,r15
	sjs	r15,callee
	l	r0,1,r15
	aisp	r15,2
	urs	r15

; A call must preserve R14.
	global	probe_saved
probe_saved
	pshm	r14,r14
	lisp	r14,9
	sjs	r15,callee
	lr	r0,r14
	popm	r14,r14
	urs	r15

; A call may change R6, so the 9 must not reach the return. R1 wouldn't show this: it's
; part of the R0+R1 result, so it counts as changed whatever the convention says about it.
	global	probe_killed
probe_killed
	lisp	r6,9
	sjs	r15,callee
	lr	r0,r6
	urs	r15

	global	callee
callee
	urs	r15

	end

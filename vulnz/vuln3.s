	.file	"vuln3.c"
	.text
	.globl	copyData
	.type	copyData, @function
copyData:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$64, %rsp
	movq	%rdi, -56(%rbp)
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	movq	-56(%rbp), %rdx
	leaq	-48(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcpy@PLT
	movl	$0, %eax
	movq	-8(%rbp), %rcx
	xorq	%fs:40, %rcx
	je	.L3
	call	__stack_chk_fail@PLT
.L3:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	copyData, .-copyData
	.section	.rodata
	.align 8
.LC0:
	.string	"[*] invalid arguments!\n [*] > %s file_name\n"
.LC1:
	.string	"opening file"
.LC2:
	.string	"rb"
.LC3:
	.string	"file not opened %s"
.LC4:
	.string	"file opened"
	.text
	.globl	main
	.type	main, @function
main:
.LFB6:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$752, %rsp
	movl	%edi, -740(%rbp)
	movq	%rsi, -752(%rbp)
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	cmpl	$2, -740(%rbp)
	je	.L5
	movq	-752(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, %rsi
	leaq	.LC0(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	movl	$0, %edi
	call	exit@PLT
.L5:
	leaq	.LC1(%rip), %rdi
	call	puts@PLT
	movq	-752(%rbp), %rax
	addq	$8, %rax
	movq	(%rax), %rax
	leaq	.LC2(%rip), %rsi
	movq	%rax, %rdi
	call	fopen@PLT
	movq	%rax, -728(%rbp)
	cmpq	$0, -728(%rbp)
	jne	.L6
	call	__errno_location@PLT
	movl	(%rax), %eax
	movl	%eax, %edi
	call	strerror@PLT
	movq	%rax, %rdx
	movq	stderr(%rip), %rax
	leaq	.LC3(%rip), %rsi
	movq	%rax, %rdi
	movl	$0, %eax
	call	fprintf@PLT
	movl	$0, %eax
	jmp	.L8
.L6:
	leaq	.LC4(%rip), %rdi
	call	puts@PLT
	movq	-728(%rbp), %rdx
	leaq	-720(%rbp), %rax
	movq	%rdx, %rcx
	movl	$1, %edx
	movl	$699, %esi
	movq	%rax, %rdi
	call	fread@PLT
	movq	-728(%rbp), %rax
	movq	%rax, %rdi
	call	fclose@PLT
	leaq	-720(%rbp), %rax
	movq	%rax, %rdi
	call	copyData
	movl	$0, %eax
.L8:
	movq	-8(%rbp), %rcx
	xorq	%fs:40, %rcx
	je	.L9
	call	__stack_chk_fail@PLT
.L9:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits

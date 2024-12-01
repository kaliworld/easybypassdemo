.code

EXTERN SW3_GetSyscallNumber: PROC

EXTERN SW3_GetRandomSyscallAddress: PROC

Sw3NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 009937F7Dh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 009937F7Dh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtAllocateVirtualMemory ENDP

Sw3NtProtectVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 035AF392Bh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 035AF392Bh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtProtectVirtualMemory ENDP

Sw3NtWriteVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 04592316Dh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 04592316Dh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtWriteVirtualMemory ENDP

Sw3NtQueueApcThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01E01843Fh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 01E01843Fh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQueueApcThread ENDP

end
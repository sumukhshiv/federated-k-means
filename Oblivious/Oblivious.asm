; ===------------ Oblivious.asm - MASM libOblivious primitives ------------===//
;
;                            Covert C++ Extensions
;
;  This file is distributed under the University of Illinois Open Source
;  License. See LICENSE.TXT for details.
;
; ===----------------------------------------------------------------------===//

.CODE

; For all o_copy_i* procedures, the argument-to-register map is as follows:
; cond: "c"
; left: "d"
; right: "r8"

__o_copy_i8 PROC PUBLIC
  mov al, dl
  test ecx, -1
  cmovz ax, r8w
  ret
__o_copy_i8 ENDP

__o_copy_i16 PROC PUBLIC
  mov ax, dx
  test ecx, -1
  cmovz ax, r8w
  ret
__o_copy_i16 ENDP

__o_copy_i32 PROC PUBLIC
  mov eax, edx
  test ecx, -1
  cmovz eax, r8d
  ret
__o_copy_i32 ENDP

__o_copy_i64 PROC PUBLIC
  mov rax, rdx
  test ecx, -1
  cmovz rax, r8
  ret
__o_copy_i64 ENDP

; For all o_swap_i* procedures, the argument-to-register map is as follows:
; cond: "c"
; left: "d"
; right: "r8"
; _left: "r9"
; _right: "r10"
; _tmp: "r11"

__o_swap_i8 PROC PUBLIC
  test ecx, -1
  mov r10b, BYTE PTR [r8]
  mov r9b, BYTE PTR [rdx]
  mov r11b, r9b
  cmovnz r9w, r10w
  cmovnz r10w, r11w
  mov BYTE PTR [rdx], r9b
  mov BYTE PTR [r8], r10b
  ret
__o_swap_i8 ENDP

__o_swap_i16 PROC PUBLIC
  test ecx, -1
  mov r10w, WORD PTR [r8]
  mov r9w, WORD PTR [rdx]
  mov r11w, r9w
  cmovnz r9w, r10w
  cmovnz r10w, r11w
  mov WORD PTR [rdx], r9w
  mov WORD PTR [r8], r10w
  ret
__o_swap_i16 ENDP

__o_swap_i32 PROC PUBLIC
  test ecx, -1
  mov r10d, DWORD PTR [r8]
  mov r9d, DWORD PTR [rdx]
  mov r11d, r9d
  cmovnz r9d, r10d
  cmovnz r10d, r11d
  mov DWORD PTR [rdx], r9d
  mov DWORD PTR [r8], r10d
  ret
__o_swap_i32 ENDP

__o_swap_i64 PROC PUBLIC
  test ecx, -1
  mov r10, QWORD PTR [r8]
  mov r9, QWORD PTR [rdx]
  mov r11, r9
  cmovnz r9, r10
  cmovnz r10, r11
  mov QWORD PTR [rdx], r9
  mov QWORD PTR [r8], r10
  ret
__o_swap_i64 ENDP

END

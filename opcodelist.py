list_xor_rax = ["4831c0", "4829c0"] # List "xor rax, rax"
list_xor_rbx = ["4831db", "4829db"] # List "xor rbx, rbx"
list_xor_rcx = ["4831c9", "4829c9"] # List "xor rcx, rcx"
list_xor_rdi = ["4831ff", "4829ff"] # List "xor rdi, rdi"
list_xor_rsi = ["4831f6", "4829f6"] # List "xor rsi, rsi"
list_xor_rdx = ["4831d2", "4829d2"] # List "xor rdx, rdx"
list_syscall = ["0f05"] # List Syscall

list_mov_al_29 = ["b029", "b028fec0", "b02afec8", "b029fec0fec8"] # List "mov al, 0x29" and "mov al, 0x29; inc al"
list_mov_bl_02 = ["b302", "b301fec3", "b303fecb", "b302fec3fecb"] # List "mov bl, 0x02" and "mov bl, 0x01; inc bl"
list_mov_rdi = ["4889df", "4831ff48ffc748ffc7"] # List "mov rdi, rbx" and "xor rdi, rdi; inc rdi; inc rdi"
list_mov_bl_01 = ["b301", "b302fecb", "b302fecb", "b301fec3fecb"] # List "mov bl, 0x01" and "mov bl, 0x02; dec bl"
list_mov_rsi = ["4889de", "4831f648ffc6"] # List "mov rsi, rbx" and "xor rsi, rsi; inc rsi"

list_mov_rdi_rax = ["4889c7", "505f"] # List "mov rdi, rax" and "push rax; pop rdi"
list_mov_r10_rax = ["4989c2", "50415a"] # List "mov r10, rax" and "push rax; pop r10"
list_mov_al_02 = ["b02a", "b029fec0", "b02bfec8", "b02afec0fec8"] # List "mov al, 0x2a"
list_push_rbx = ["53"] # List push rbx
list_mov_esi_02 = ["be80ffff20", "be81ffff20ffce", "be80ffff20ffc6ffce"] 
list_sub_esi_01 = ["81ee01ffff10"] 
list_pushw_01 = ["6668231d"]
list_pushw_02 = ["666a02"]
list_mov_rsi_rsp = ["4889e6", "545e"] # List "mov rsi, rsp" and "push rsp; pop rsi"
list_mov_dl_24 = ["b218", "b223fec2", "b225feca", "b224fec2feca"] # List "mov dl, 24" and "mov dl, 23; inv dl"

list_mov_al_21 = ["b021", "b022fec8", "b020fec0", "b021fec0fec8"] # List "mov al, 0x21" and "mov al, 0x22; dec al"
list_mov_rdi_r10 = ["4c89d7", "41525f"] # List "mov rdi, r10" and "push r10; pop rdi"
list_inc_rsi = ["48ffc6", "48ffc648ffc648ffce", "48ffc648ffc648ffc648ffce48ffce", "48ffc648ffce48ffc648ffce48ffc6"] # List "inc rsi" and "inc rsi; inc rsi; dec rsi"

list_mov_68 = ["48bb2f2f62696e2f7368"]
list_push_rax = ["50"] # push rax
list_mov_rdi_rsp = ["4889e7", "545f"] # List "mov rdi, rsp" and "push rsp; pop rdi"
list_push_rdi = ["57"] # push rdi
list_mov_al_03b = ["b03b", "b03afec0", "b03cfec8", "b03bfec0fec8"] # List "mov al, 0x3b" and "mov al, 0x3a, inc al"
list_mov_al_03c = ["b03c", "b03bfec0", "b03dfec8", "b03cfec0fec8"] # List "mov al, 0x3c" and "mov al, 0x3b; inc al"
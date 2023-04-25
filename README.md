## Shellcode generator for a reverse shell
Ce script python genere un shellcode d'un reverse shell chiffrer. Il ce base sur une liste d'opcode en shellcode 

Liste Opcode (opcodelist.py):

```sh
list_xor_rax = ["4831c0", "4829c0"] # List "xor rax, rax"
```

Modification et lancement du script de test du shellcode :
```sh
shellcode = input("Insert shellcode here")
```

```sh
./TestShellcode.c
```
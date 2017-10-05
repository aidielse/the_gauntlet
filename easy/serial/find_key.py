import angr

# This is the old angr API... v6.7.1.13

def fflush_hook(state):
    state.regs.rip = 0x400eb9

def setvbuf_hook(state):
    state.regs.rip = 0x400ed7

def calloc_hook(state):
    state.regs.rip = 0x400ee6

def printf_hook(state):
    state.regs.rip = 0x400f16

# create angr project
proj = angr.Project("./serial", load_options={"auto_load_libs":False})

# skip over these functions
proj.hook(0x400eb4, fflush_hook)
proj.hook(0x400ed2, setvbuf_hook)
proj.hook(0x400ee1, calloc_hook)
proj.hook(0x400f11, printf_hook)

# start 
st = proj.factory.entry_state()

# Constrain the first 12 bytes to be the characters 0 through 9:
for _ in xrange(12):
    k = st.posix.files[0].read_from(1)
    st.se.add(k >= 0x30)
    st.se.add(k <= 0x39)

# Constrain the last byte to be a newline
k = st.posix.files[0].read_from(1)
st.se.add(k == 10)

# Reset the symbolic stdin's properties and set its length.
st.posix.files[0].seek(0)
st.posix.files[0].length = 13

pg = proj.factory.path_group(st)
# find a solution
pg.explore(find=0x400e5c, avoid=(0x400e78, 0x400d22))

# extract key from sol
key = pg.found[0].state.posix.dumps(0).split("\n")[0]

print "KEY: " + key

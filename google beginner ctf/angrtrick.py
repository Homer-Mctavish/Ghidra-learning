import angr
import claripy

base_address = 0x00100000

success_address = 0x0010111d
failure_address = 0x00101100

FLAG_LEN = 15
STDIN_FD = 0

project = angr.Project("./a.out", main_opts={'base_addr': base_address}) 

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')]) # newline in the bitvector value class so stdin can accept our concatenated bit vector symbolic *flag_chars

state = project.factory.full_init_state(
    args=['./a.out'],
    add_options=angr.options.unicorn,
    stdin=flag,
)

for k in flag_chars:
    state.solver.add(k >= ord('!'))
    state.solver.add(k <= ord('~'))

simgr = project.factory.simulation_manager(state)
simgr.explore(find=success_address, avoid=failure_address)

if(len(simgr.found) > 0):
    for found in simgr.found:
        print(found.posix.dumps(STDIN_FD))

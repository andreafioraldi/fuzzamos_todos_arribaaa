#!/usr/bin/env python3

import os
import angr
import glob
import signal
import angrgdb

try: input_dir
except:
    input_dir = input("Insert AFL input directory: ")
    if not os.path.exists(input_dir):
        raise ValueError('no such directory')

project = angrgdb.reload_project()

class DoNothing(angr.SimProcedure):
	def run(self):
		return

afl_functions = [
    "__afl_maybe_log",
    "__afl_setup",
    "__afl_setup_first",
    "__afl_store",
    "__afl_die",
    "__afl_forkserver",
    "__afl_fork_wait_loop",
    "__afl_fork_resume",
    "__afl_setup_abort",
    "__afl_return",
]
map(lambda f: project.hook_symbol(f, DoNothing()), afl_functions)

init_state = angrgdb.StateShot(sync_brk=False)
simgr = project.factory.simulation_manager(init_state, save_unconstrained=True)

flag = True

def sigint_handler(signum, frame):
    global flag
    flag = False

#signal.signal(signal.SIGINT, sigint_handler)

paths = 0

while flag:
    try:
        simgr = simgr.step()
        cur = len(simgr.active) + len(simgr.deadended) + len(simgr.unconstrained)
        if cur != paths:
            paths = cur
            print("Having", paths, "paths...")
    except Exception as e:
        print (e)
        break
    except KeyboardInterrupt:
        break

print()
print("Stopped.")

for i in range(len(simgr.active)):
    print("Saving active state", simgr.active[i])
    with open(os.path.join(glob.glob(input_dir)[0], "test_angrgdb_active_%d" % i), "wb") as f:
        f.write(simgr.active[i].posix.dumps(0))

for i in range(len(simgr.deadended)):
    print("Saving deadended state", simgr.deadended[i])
    with open(os.path.join(glob.glob(input_dir)[0], "test_angrgdb_deadended_%d" % i), "wb") as f:
        f.write(simgr.deadended[i].posix.dumps(0))

for i in range(len(simgr.unconstrained)):
    print("Saving unconstrained state", simgr.unconstrained[i])
    with open(os.path.join(glob.glob(input_dir)[0], "test_angrgdb_unconstrained_%d" % i), "wb") as f:
        f.write(simgr.unconstrained[i].posix.dumps(0))

print()
print("Created", len(simgr.active)+len(simgr.deadended)+len(simgr.unconstrained), "inputs.")


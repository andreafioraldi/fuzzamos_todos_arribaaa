#!/usr/bin/env python

from pwn import *

import re
import glob
import signal
import time
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-i", dest="input", required=True, help="AFL input directory")
    p.add_argument("-b", dest="bpt", required=True, help="breakpoint in which start symbolic exploration")
    p.add_argument("cmd", nargs="+", help="cmdline")
    return p.parse_args()

def check_args(args):
    if not os.path.exists(args.input):
        raise ValueError('no such directory')


args = parse_args()
check_args(args)

try:
    try: bpt = int(args.bpt, 16)
    except: bpt = int(args.bpt)
except:
    raise ValueError('the breakpoint is not an address')

gdb_args = ["gdb", "-q", "-nh", "-ex", "b *0x%x" % bpt, "-ex", "run", "-ex", "python input_dir='%s'" % args.input, "-x", os.path.dirname(os.path.realpath(__file__)) + "/angrgdb_inputs.py"]

test_input = ""

def patched_send(self, data):
    global test_input
    if len(data) > 0:
        test_input += data
    
    if self.isEnabledFor(logging.DEBUG):
        self.debug('Sent %#x bytes:' % len(data))
        if len(set(data)) == 1:
            self.indented('%r * %#x' % (data[0], len(data)))
        elif all(c in string.printable for c in data):
            for line in data.splitlines(True):
                self.indented(repr(line), level = logging.DEBUG)
        else:
            self.indented(fiddling.hexdump(data), level = logging.DEBUG)
    self.send_raw(data)

process.send = patched_send

context.log_level = "error"

p = process(gdb_args + args.cmd, stdin=PTY, stdout=PTY, stderr=PTY)
p.interactive("")

os.kill(p.pid, signal.SIGINT)

p.recvuntil("inputs.\n")
p.close()

for d in os.listdir(args.input):
    if d.startswith("test_angrgdb"):
        with open(os.path.join(args.input, d), "rb") as f:
            content = f.read()
        with open(os.path.join(args.input, d), "wb") as f:
            f.write(test_input + content)




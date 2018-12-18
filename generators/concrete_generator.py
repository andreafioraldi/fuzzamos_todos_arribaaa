#!/usr/bin/env python

from pwn import *

import re
import glob
import time
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-i", dest="input", required=True, help="AFL input directory")
    p.add_argument("cmd", nargs="+", help="cmdline")
    return p.parse_args()

def check_args(args):
    if not os.path.exists(args.input):
        raise ValueError('no such directory')


args = parse_args()
check_args(args)

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

p = process(args.cmd, stdin=PTY, stdout=PTY, stderr=PTY, shell=True)
p.interactive("")

with open(os.path.join(glob.glob(args.input)[0], "test_%d" % time.time()), "wb") as f:
    f.write(test_input)


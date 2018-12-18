#!/usr/bin/env python2
import atexit
import argparse
import logging
import functools
import hashlib
import json
import os
import pickle
import shutil
import subprocess as sp
import sys
import tempfile
import time

import pyinotify
import qsym

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-o", dest="output", required=True, help="AFL output directory")
    p.add_argument("-a", dest="afl", required=True, help="AFL name")
    p.add_argument("-n", dest="name", required=True, help="Qsym name")
    p.add_argument("-f", dest="filename", default=None)
    p.add_argument("-m", dest="mail", default=None)
    p.add_argument("-b", dest="asan_bin", default=None)
    p.add_argument("-Q", dest="qemu_mode", action="store_const", const=True, default=False, help="set if AFL is using qemu mode")
    p.add_argument("cmd", nargs="+", help="cmdline, use %s to denote a file" % qsym.utils.AT_FILE)
    return p.parse_args()

def check_args(args):
    if not os.path.exists(args.output):
        raise ValueError('no such directory')

def main():
    args = parse_args()
    check_args(args)
    
    if os.getenv("AFL_PATH") is not None:
        afl_path = os.environ["AFL_PATH"]
    else:
        afl_path = os.path.dirname(os.path.realpath(__file__)) + "/../afl/"
        afl_path = af_path if os.path.isdir(afl_path) else None
    
    e = qsym.afl.AFLExecutor(args.cmd, args.output, args.afl,
            args.name, args.filename, args.mail, args.asan_bin, args.qemu_mode, afl_path)
    try:
        e.run()
    finally:
        e.cleanup()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()

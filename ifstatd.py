#!/usr/bin/env python
#
# xdp_redirect_cpu.py Redirect the incoming packet to the specific CPU
#
# Copyright (c) 2018 Gary Lin
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import time
import sys

flags = 0
def usage():
    print("Usage: {0} <in ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    usage()

in_if = sys.argv[1]

# load BPF program
b = BPF(src_file = "ifstat_kern.c", cflags = [
  "-DANY=-1",
  "-DFILTER0_ENABLED=1",
  "-DFILTER0_SRC_IP=-1",
  "-DFILTER0_DST_IP=-1",
  "-DFILTER0_SRC_PORT=-1",
  "-DFILTER0_DST_PORT=-1",
  "-DFILTER0_IPPROTO=-1"
])

in_fn = b.load_func("xdp_packet_handler", BPF.XDP)
b.attach_xdp(in_if, in_fn, flags)

dropcnt = b.get_table("filter0")
while 1:
    try:
        for k in dropcnt.keys():
            print("abc", dropcnt[k])
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

b.remove_xdp(in_if, flags)

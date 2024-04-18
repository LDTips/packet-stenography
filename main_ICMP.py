from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import sr1
import os
from time import perf_counter, sleep
import base64

p_queue = []
msg = 'hello'
if len(msg) % 2 != 0:  # Padding in order for splitting to work
    msg += '.'

msg = [msg[i:i+2] for i in range(0, len(msg), 2)]  # Split msg into chunks of 2 characters

# for c in msg:
#     print(hex(ord(c)))
t1 = perf_counter()
for i, c in enumerate(msg):
    letter_hex = hex(ord(c[0]))[2:] + hex(ord(c[1]))[2:]
    while True:
        # urandom(40) gives 56 bytes (typical for Linux), urandom(24) gives 32 (typical for Windows)
        p = ICMP(id=0x1337, seq=i+1) / Raw(load=base64.b64encode(os.urandom(40)))
        del p.chksum
        p = p.__class__(bytes(p))
        match_hex = hex(p.chksum)[2:]
        if match_hex == letter_hex:
            p = IP(dst='127.0.0.1') / p
            p_queue.append(p)
            t2 = perf_counter()
            print(f"Found match {c}<->{match_hex} after {t2 - t1} s")
            break

for pkt in p_queue:
    sr1(pkt, timeout=1, verbose=False)



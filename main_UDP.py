from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1
import os
from time import perf_counter, sleep
import base64
from random import randint, uniform

# DOUBLE_BYTE_MODE mode takes longer, but encapsulates two letters in single checksum rather than single
# Only good for smaller messages
DOUBLE_BYTE_MODE = False

msg = 'Hello this is a test message'
if DOUBLE_BYTE_MODE:
    if len(msg) % 2 != 0:  # Padding in order for splitting to work
        msg += '.'
    msg = [msg[i:i + 2] for i in range(0, len(msg), 2)]  # Split msg into chunks of 2 characters

p_queue = []
for i, letter in enumerate(msg):
    t1 = perf_counter()
    while True:
        random_bytes = os.urandom(32)
        right = True
        if int(random_bytes[-1]) % 2 != 0:
            right = False
        p = IP(dst='127.0.0.1') / UDP(dport=7) / Raw(load=random_bytes)
        p = IP(raw(p))  # Compile the packet to calculate chksum

        packet_hex = hex(p[UDP].chksum)[4:] if right else hex(p[UDP].chksum)[2:4]
        letter_hex = hex(ord(letter))[2:]
        if DOUBLE_BYTE_MODE:
            packet_hex = hex(p[UDP].chksum)[2:]
            c0, c1 = ord(letter[0]), ord(letter[1])
            letter_hex = hex(c0)[2:] + hex(c1)[2:] if right else hex(c1)[2:] + hex(c0)[2:]

        if packet_hex == letter_hex:
            p_queue.append(p)
            t2 = perf_counter()
            print(f"Found match after {t2 - t1} s.", end='')
            if DOUBLE_BYTE_MODE:
                print(f"{'Swapped' if not right else ''}")
            else:
                print(f"{'right' if right else 'left'}")
            break

# Separate packet array into array of packet bursts (smaller arrays)
p_bursts = []
while p_queue:
    length = randint(10, 50)
    p_b, p_queue = p_queue[:length], p_queue[length:]
    p_bursts.append(p_b)

for pkts in p_bursts:
    for p in pkts:
        sr1(p, timeout=uniform(0.1, 0.2), verbose=False)
    sleep(randint(2, 5))



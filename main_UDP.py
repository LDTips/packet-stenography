from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1
import os
from time import perf_counter, sleep
import base64
from random import randint, uniform


def xor(a, b):
    return bytes([a ^ b for a, b in zip(a, b)])

msg = 'Hello this is a test message'
BLOCK_SIZE = 128
while len(msg) % BLOCK_SIZE != 0:  # Padding in order for splitting to work
    msg += '.'
msg = [msg[i:i + BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]  # Split msg into chunks

p_queue = []
for i, c in enumerate(msg):
    # p1 - packet with XOR bytes, p2 packet with data (XORed with the p1 checksum)
    t1 = perf_counter()
    random_bytes = os.urandom(BLOCK_SIZE*2)
    p1 = IP(dst='127.0.0.1') / UDP(sport=31245, dport=80) / Raw(load=random_bytes)
    p1 = IP(raw(p1))  # Compile the packet to calculate chksum

    xor_pattern = bytes.fromhex((BLOCK_SIZE//2)*hex(p1[UDP].chksum)[2:])
    xored_data = xor(xor_pattern, c.encode('ANSI'))
    print(f"XORed {xor_pattern} and {xored_data}")
    p2 = IP(dst='127.0.0.1') / UDP(sport=31245, dport=80) / Raw(load=xored_data+os.urandom(BLOCK_SIZE))
    p_queue.append(p1)
    p_queue.append(p2)

# Separate packet array into array of packet bursts (smaller arrays)
p_bursts = []
while p_queue:
    length = randint(10, 50)
    p_b, p_queue = p_queue[:length], p_queue[length:]
    p_bursts.append(p_b)

for pkts in p_bursts:
    for p in pkts:
        sr1(p, timeout=uniform(0.1, 0.2), verbose=False)
    sleep(randint(2, 4))



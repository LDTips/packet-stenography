from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1
import os
from time import perf_counter, sleep
import base64
from random import randint, uniform

UDP_SRC_IP='192.168.1.14'
UDP_DST_IP='192.168.1.19'


def xor(a, b):
    return bytes([a ^ b for a, b in zip(a, b)])


with open('antygona.txt', 'r', encoding='ANSI') as file:
    msg = file.read()

MSG_SIZE = 64
while len(msg) % MSG_SIZE != 0:  # Padding in order for splitting to work
    msg += '.'
msg = [msg[i:i + MSG_SIZE] for i in range(0, len(msg), MSG_SIZE)]  # Split msg into chunks

p_queue = []
for i, c in enumerate(msg):
    # p1 - packet with XOR bytes, p2 packet with data (XORed with the p1 checksum)
    t1 = perf_counter()
    random_bytes = os.urandom(MSG_SIZE)
    p1 = IP(src=UDP_SRC_IP, dst=UDP_DST_IP) / UDP(sport=65123, dport=80) / Raw(load=random_bytes)
    p1 = IP(raw(p1))  # Compile the packet to calculate chksum
    p2 = IP(src=UDP_SRC_IP, dst=UDP_DST_IP) / UDP(sport=65123, dport=80) / Raw(load=os.urandom(MSG_SIZE*4))
    # b1xb2xb3xb4xb5xb6
    # c1c2c1c2c1
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
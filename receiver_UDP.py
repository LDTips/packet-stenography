import socket
from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

# UDP_DST_IP='127.0.0.1'
UDP_SRC_IP = '192.168.1.14'
UDP_DST_IP = '192.168.1.19'
UDP_SRC_PORT=65123
UDP_DST_PORT=80
MSG_SIZE = 64

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_DST_IP, UDP_DST_PORT))


antygona = b''
def xor(a, b):
    return bytes([a ^ b for a, b in zip(a, b)])

while True:
    data, address = sock.recvfrom(1024)
    if(len(data) == MSG_SIZE):
        p1 = IP(src=UDP_SRC_IP, dst=UDP_DST_IP) / UDP(sport=UDP_SRC_PORT, dport=UDP_DST_PORT) / Raw(load=data)
        p1 = IP(raw(p1))
        checksum = hex(p1[UDP].chksum)
    else:
        new_xored_data = b''
        for i in range(MSG_SIZE):
            new_xored_data += data[i*2].to_bytes(1, 'big')
        xor_pattern = bytes.fromhex((MSG_SIZE // 2) * checksum[2:].zfill(4))
        data = xor(new_xored_data, xor_pattern)
        if b'....' in data:
            antygona += data[:64].split(b'....')[0]
            f = open('odszyfrowane.txt', 'w')
            f.write(antygona.decode('iso_8859_1'))
            exit(0)
        antygona += data[:64]
        print(data.decode('iso_8859_1'))

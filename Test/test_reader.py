from scapy.all import PcapReader
import time
import os

with open('/tmp/test.cap', 'wb') as f:
    f.write(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00') # PCAP header

reader = PcapReader('/tmp/test.cap')
print("Reading...")
pkts = list(reader)
print(f"Packets read: {len(pkts)}")

# Append a packet
with open('/tmp/swcli_cap-04.cap', 'rb') as f:
    f.seek(24) # Skip header
    pkt_data = f.read(100) # Read one packet
    with open('/tmp/test.cap', 'ab') as out:
        out.write(pkt_data)

print("Reading again...")
pkts = list(reader)
print(f"Packets read: {len(pkts)}")

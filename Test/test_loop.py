import time
from scapy.all import PcapReader
import shutil
import os

shutil.copy('/tmp/swcli_cap-01.cap', '/tmp/test_loop.cap')
f = open('/tmp/test_loop.cap', 'rb')
reader = PcapReader(f)

print("First read:")
count = 0
for p in reader:
    count += 1
print(f"Read {count} pkts.")

print("Appending data...")
with open('/tmp/swcli_cap-05.cap', 'rb') as source:
    source.seek(24) # Skip header
    data = source.read()
    with open('/tmp/test_loop.cap', 'ab') as dest:
        dest.write(data)

print("Second read after append:")
count = 0
for p in reader:
    count += 1
print(f"Read {count} pkts.")

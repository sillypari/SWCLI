from scapy.all import PcapReader
import shutil

shutil.copy('/tmp/swcli_cap-01.cap', '/tmp/test_iter.cap')
f = open('/tmp/test_iter.cap', 'rb')
reader = PcapReader(f)

c1 = 0
for p in reader: c1 += 1
print(f"First read: {c1}")

c2 = 0
for p in reader: c2 += 1
print(f"Second read without append: {c2}")

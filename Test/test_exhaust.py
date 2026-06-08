from scapy.all import PcapReader
import shutil

# Make a copy of cap-01 (1527 bytes, 12 packets)
shutil.copy('/tmp/swcli_cap-01.cap', '/tmp/test_exhaust.cap')

reader = PcapReader('/tmp/test_exhaust.cap')
print("First pass:")
for p in reader:
    pass
print("Done first pass.")

print("Appending data...")
with open('/tmp/swcli_cap-05.cap', 'rb') as f:
    f.seek(24) # Skip header
    data = f.read(1000)
    with open('/tmp/test_exhaust.cap', 'ab') as out:
        out.write(data)

print("Second pass:")
count = 0
for p in reader:
    count += 1
print(f"Read {count} packets on second pass.")


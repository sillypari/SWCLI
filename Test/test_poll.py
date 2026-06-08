from scapy.all import PcapReader
from scapy.layers.eap import EAPOL

def is_m1(key) -> bool:
    return (getattr(key, "key_type", 0) == 1 and getattr(key, "install", 0) == 0 and getattr(key, "key_ack", 0) == 1 and getattr(key, "has_key_mic", 0) == 0 and getattr(key, "secure", 0) == 0)

def is_m2(key) -> bool:
    return (getattr(key, "key_type", 0) == 1 and getattr(key, "install", 0) == 0 and getattr(key, "key_ack", 0) == 0 and getattr(key, "has_key_mic", 0) == 1 and getattr(key, "secure", 0) == 0)

def is_m3(key) -> bool:
    return (getattr(key, "key_type", 0) == 1 and getattr(key, "install", 0) == 1 and getattr(key, "key_ack", 0) == 1 and getattr(key, "has_key_mic", 0) == 1 and getattr(key, "secure", 0) == 1)

def is_m4(key) -> bool:
    return (getattr(key, "key_type", 0) == 1 and getattr(key, "install", 0) == 0 and getattr(key, "key_ack", 0) == 0 and getattr(key, "has_key_mic", 0) == 1 and getattr(key, "secure", 0) == 1)

reader = PcapReader('/tmp/swcli_cap-05.cap')
m1 = m2 = m3 = m4 = False
count = 0
for pkt in reader:
    if pkt.haslayer(EAPOL):
        count += 1
        eapol_key = pkt[EAPOL].payload
        print("Got EAPOL:", count)
        if hasattr(eapol_key, "key_ack"):
            print("  has key_ack")
            if is_m1(eapol_key): 
                m1 = True
                print("  is M1")
            if is_m2(eapol_key): 
                m2 = True
                print("  is M2")
            if is_m3(eapol_key): 
                m3 = True
                print("  is M3")
            if is_m4(eapol_key): 
                m4 = True
                print("  is M4")
        else:
            print("  no key_ack!")
print(f"Final: m1={m1}, m2={m2}, m3={m3}, m4={m4}")

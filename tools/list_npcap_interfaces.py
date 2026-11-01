
import ctypes
from ctypes import POINTER, Structure, c_char_p, c_int, c_uint

class PcapIf(Structure):
    pass

PcapIf._fields_ = [
    ("next", POINTER(PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", c_uint),
]

pcap = ctypes.WinDLL(
    r"C:\Windows\System32\Npcap\wpcap.dll"
)

pcap.pcap_findalldevs.argtypes = [
    POINTER(POINTER(PcapIf)),
    ctypes.c_char_p,
]
pcap.pcap_findalldevs.restype = c_int

pcap.pcap_freealldevs.argtypes = [POINTER(PcapIf)]

devices = POINTER(PcapIf)()
errbuf = ctypes.create_string_buffer(256)

result = pcap.pcap_findalldevs(
    ctypes.byref(devices),
    errbuf,
)

if result != 0:
    print("Npcap error:", errbuf.value.decode(errors="replace"))
else:
    try:
        item = devices
        while item:
            device = item.contents
            print("Name:", device.name.decode(errors="replace"))
            print(
                "Description:",
                device.description.decode(errors="replace")
                if device.description
                else "(no description)",
            )
            print()
            item = device.next
    finally:
        if devices:
            pcap.pcap_freealldevs(devices)


import psutil

print("Available network interfaces:\n")

for name, addresses in psutil.net_if_addrs().items():
    print(f"Interface: {name}")

    for address in addresses:
        if address.family.name in ("AF_INET", "AF_INET6"):
            print(f"  IP address: {address.address}")

    stats = psutil.net_if_stats().get(name)
    if stats:
        print(f"  Active: {stats.isup}")

    print()

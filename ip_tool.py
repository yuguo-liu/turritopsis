nodes = '''
i-091928dad78073a3b	3.92.79.67	172.31.24.145
i-0e19c97b83e3f9aef	3.139.101.186	172.31.33.130
i-0b393c4b92ee98511	13.57.213.118	172.31.11.110
i-025888461b3dcdd32	54.244.131.193	172.31.18.70
i-0c21ae6b7b7b926fe	54.251.225.53	172.31.35.140
i-08d397d681419846f	18.153.97.47	172.31.25.240
i-070248e5945abce7d	18.201.162.20	172.31.22.0
i-0c01aa73f5bbed650	35.180.116.95	172.31.44.244
i-052bc8ace596ca8d9	16.170.155.102	172.31.28.48
i-09fec05cb117ec2ae	18.212.216.235	172.31.25.120
i-09a4d03f0f3d0ff69	13.59.236.231	172.31.43.211

'''

num_regions = 16
N = 9

n = int(N / num_regions)
r = N - num_regions * n

each_region_n = []
for i in range(num_regions):
    if r > 0:
        each_region_n.append(n + 1)
        r -= 1
    else:
        each_region_n.append(n)
print(each_region_n)

public_ips = []
private_ips = []

for line in nodes.splitlines():
    try:
        _, public, private = line.split()
        public_ips.append(public)
        private_ips.append(private)
    except:
        pass

print("N=%d" % len(public_ips))

print("# public IPs")
print("pubIPsVar=(", end='')
for i in range(len(public_ips) - 1):
    print("[%d]=\'%s\'" % (i, public_ips[i]))
i = len(public_ips) - 1
print("[%d]=\'%s\')" % (i, public_ips[i]))

print("# private IPs")
print("priIPsVar=(", end='')
for i in range(len(private_ips) - 1):
    print("[%d]=\'%s\'" % (i, private_ips[i]))
i = len(private_ips) - 1
print("[%d]=\'%s\')" % (i, private_ips[i]))
nodes = '''
i-06d07f69250b80369	54.82.37.146	172.31.16.232
i-08e50c8b28c68f90f	3.90.222.231	172.31.16.249
i-0e0193b9600d648c5	18.216.147.50	172.31.36.208
i-03940959c1db3774b	3.101.147.45	172.31.3.93
i-070a1c951f4313fda	44.246.29.87	172.31.19.16
i-04b1d484ef0221851	13.234.21.22	172.31.7.52
i-0387c034dee9a9496	13.125.230.117	172.31.7.115
i-0f439c649eac418d7	13.212.217.232	172.31.39.254
i-049bbe59ffa346465	52.62.252.208	172.31.12.76
i-045b22371fe75e4db	3.112.196.6	172.31.32.9
i-094a73372dd86d080	3.96.63.128	172.31.8.21
i-02875b5c07de00a51	3.69.238.194	172.31.28.202
i-0a5688862f405a29d	54.154.103.86	172.31.16.137
i-0df75075a187a5602	18.175.145.29	172.31.22.74
i-0285f1698e9790dfa	13.38.7.255	172.31.44.137
i-053d809529b49cc22	56.228.4.78	172.31.20.64
i-06200d0ac1a8dd174	18.228.44.222	172.31.1.197
i-063a817bc25350224	107.20.130.40	172.31.16.45
i-022942cf23a11d472	54.157.20.251	172.31.25.44

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
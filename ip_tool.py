nodes = '''
i-04eb35a131a8dcc5a	34.229.91.14	172.31.18.196
i-09a8b9ff45d5905cd	54.226.165.198	172.31.20.195
i-0e0193b9600d648c5	18.216.147.50	172.31.36.208
i-03940959c1db3774b	3.101.147.45	172.31.3.93
i-070a1c951f4313fda	44.246.29.87	172.31.19.16
i-04b1d484ef0221851	13.234.21.22	172.31.7.52
i-0613bc8b7a979facf	3.35.133.178	172.31.6.169
i-0f439c649eac418d7	13.212.217.232	172.31.39.254
i-09c8c925fdb61733e	54.252.244.154	172.31.15.37
i-00e7bc24844154ef9	18.183.132.8	172.31.42.155
i-094a73372dd86d080	3.96.63.128	172.31.8.21
i-054708021e791a0f5	54.93.101.207	172.31.27.10
i-0a5688862f405a29d	54.154.103.86	172.31.16.137
i-0d89908948f187f19	18.135.101.23	172.31.20.211
i-0285f1698e9790dfa	13.38.7.255	172.31.44.137
i-053d809529b49cc22	56.228.4.78	172.31.20.64
i-06200d0ac1a8dd174	18.228.44.222	172.31.1.197
i-0ec611df55c7ad1d6	34.234.79.34	172.31.31.30
i-054fb4fdf19651b26	18.224.181.120	172.31.40.50
i-0458a718ad9928095	54.215.144.118	172.31.3.119
i-060f50dcb7729eb70	35.88.159.221	172.31.28.29
i-0414b1f82aabc0e7e	13.203.195.57	172.31.11.104
i-051fb67e8ee9a9b93	3.35.219.129	172.31.14.183

'''

num_regions = 16
N = 60

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
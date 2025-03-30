nodes = '''
i-06d07f69250b80369	54.82.37.146	172.31.16.232
i-0e0193b9600d648c5	18.216.147.50	172.31.36.208
i-03940959c1db3774b	3.101.147.45	172.31.3.93
i-070a1c951f4313fda	44.246.29.87	172.31.19.16
i-0f439c649eac418d7	13.212.217.232	172.31.39.254
i-02875b5c07de00a51	3.69.238.194	172.31.28.202
i-0a5688862f405a29d	54.154.103.86	172.31.16.137
i-0285f1698e9790dfa	13.38.7.255	172.31.44.137
i-053d809529b49cc22	56.228.4.78	172.31.20.64
i-08e50c8b28c68f90f	3.90.222.231	172.31.16.249

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
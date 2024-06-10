
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from collections import defaultdict

group = PairingGroup('BN254')

n = 4
t = 1
g1 = group.deserialize(b'1:AN3vaywaAbtz9oSOehDxA8kBr3lnI6FftEfi+PCpsOwB')
g1.initPP()
g2 = group.deserialize(
    b'2:DQT2Rd58uiwgldvGY+ejPIhRHLkgon8ataszIFmQZoAWMWYFc53zBiE10qgdsBKRlcBgpraYIaJ1TbdKph8VGgA=')
g2.initPP()
h1 = group.deserialize(
    b'2:FEm/7O39fQLLEp6lQ1ySiom5RENmbCRg0WSWjGF0GIEJ47Oa8N6nwqUnVY6nIHXGBLS80RDhn6jfi7y/q33nRgE=')
h1.initPP()
u1 = group.deserialize(
    b'2:Blbg+VOpWJ9ZTDxtRgPI2/V0Ot9FFoAq3k2AwjVojGsPxx63BEd+ObaAFg9aaar7M+gC1o9BO1c0CqnfGpwe8gE=')
u1.initPP()
h2 = group.deserialize(b'2:D3osZABaoUHbAy2l0qHuHbH+WXkkqdYtMd4F3YbcOjMToCpn4aAGeeTt6JXYIf0PResVdiKhboXyrqsxmoFL4gE=')
h2.initPP()
h3 = group.deserialize(b'2:CNIvmNafzuJZyjds/DU31gTnjj9vYpvNPQZDZQITYsgQzMDKs7G9mApUCIVf5MJEdDupgN/MIa7Hf81zQgXdyAA=')
h3.initPP()
h4 = group.deserialize(b'2:A885/p3qo4CH9tmFvdXbTKYhpK/Ucdl1bPTXUw1duj0Y/1+lc1RmhuJAJtqcAUxl9kV7RsTjTuGOMtZ5EFxe6AA=')
h4.initPP()

def keygen(n):
    dk = list()
    ek = list()
    ssk = list()
    vk = list()
    for i in range(n):
        dk.append(group.random(ZR))
        ek.append(h1 ** dk[i])
        ssk.append(group.random(ZR))
        vk.append(g1 ** ssk[i])
    return dk, ek, ssk, vk


dks, eks, ssks, vks = keygen(4)
fw = 2
y1 = eks[1] ** fw
a = group.init(ZR, 2)
b = group.init(ZR, 3)

sigmaset = defaultdict()

sigmaset[0] = 1
sigmaset[1] = 2
sigmaset[3] = 3
s = set()
sx = list()
for i in sigmaset.keys():
    s.add(i+1)
    sx.append(i+1)
    print(s, sx)

from utils.core.merkleTree import encode,decode


m = b'Hi, this is a test msg!'
s = encode(2, 4, m)
for i in range(4):
    print('f[%d]: %s' %(i, s[i]))

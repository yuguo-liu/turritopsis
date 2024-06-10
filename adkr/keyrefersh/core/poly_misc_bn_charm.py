from operator import mul
from functools import reduce
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from utils.core.betterpairing import ZR as ZR1
group = PairingGroup('BN254')

ZERO = group.random(ZR, seed=59)*0
ONE = group.random(ZR, seed=60)*0+1


def lagrange_c(S, j):
    """ """
    # Assert S is a subset of range(0,self.l)

    assert type(S) is set
    S = sorted(S)

    assert j in S
    num = reduce(mul, [0 - jj - 1 for jj in S if jj != j], ONE)
    den = reduce(mul, [j - jj for jj in S if jj != j], ONE)  # noqa: E272
    # assert num % den == 0
    return num / den

def lagrange_c1(S, j):
    """ """
    # Assert S is a subset of range(0,self.l)

    assert type(S) is set
    S = sorted(S)

    assert j in S
    num = reduce(mul, [0 - jj - 1 for jj in S if jj != j], ONE)
    den = reduce(mul, [j - jj for jj in S if jj != j], ONE)  # noqa: E272
    # assert num % den == 0
    return num / den


def lagrange(S, j):
    """ """
    # Assert S is a subset of range(0,self.l)
    # assert len(S) == f+1
    assert type(S) is set
    # assert S.issubset(range(0, n))
    S = sorted(S)

    assert j in S
    num = reduce(mul, [0 - jj     for jj in S if jj != j], ONE)
    den = reduce(mul, [j - jj     for jj in S if jj != j], ONE)  # noqa: E272
    # assert num % den == 0
    return num / den

def lagrange_at_x(S, j, x):
    """ """
    # Assert S is a subset of range(0,self.l)
    # assert len(S) == f+1
    assert type(S) is set
    # assert S.issubset(range(0, n))
    S = sorted(S)

    assert j in S
    num = reduce(mul, [x - jj     for jj in S if jj != j], ONE)
    den = reduce(mul, [j - jj     for jj in S if jj != j], ONE)  # noqa: E272
    # assert num % den == 0
    return num / den

def lagrange_x(S, j, x):
    """ """
    # Assert S is a subset of range(0,self.l)
    # assert len(S) == f+1
    assert type(S) is set
    # assert S.issubset(range(0, n))
    S = sorted(S)

    assert j in S
    num = reduce(mul, [x - jj     for jj in S if jj != j], ONE)
    den = reduce(mul, [j - jj     for jj in S if jj != j], ONE)  # noqa: E272
    # assert num % den == 0
    return num / den

def interpolate_g1_at_x(coords, x, one, order=-1):
    if order == -1:
        order = len(coords)
    xs = []
    sortedcoords = sorted(coords, key=lambda x: x[0])
    for coord in sortedcoords:
        xs.append(coord[0])
    s = set(xs[0:order])
    # print(s)
    # print(xs)
    # print(sortedcoords)
    out = one
    S = set(range(0, order))
    for i in S:
        a = lagrange(s, xs[i])
        # print(a, type(a))
        # print(sortedcoords[i][1], type(sortedcoords[i][1]))
        out *= (sortedcoords[i][1] ** a)
    # print("la", out)
    return out

def interpolate_at_x(coords, x, one, order=-1):
    if order == -1:
        order = len(coords)
    xs = []
    sortedcoords = sorted(coords, key=lambda x: x[0])
    for coord in sortedcoords:
        xs.append(coord[0])
    s = set(xs[0:order])

    # print(xs)
    # print(sortedcoords)
    out = one
    for i in range(len(coords)):
        item = group.init(ZR, sortedcoords[i][1]) * lagrange(s, xs[i])
        out = out + item
    # print("la", out)
    return out

def interpolate_at_x1(coords, x, one, order=-1):
    if order == -1:
        order = len(coords)
    xs = []
    sortedcoords = sorted(coords, key=lambda x: x[0])
    for coord in sortedcoords:
        xs.append(coord[0])
    s = set(xs[0:order])

    # print(xs)
    # print(sortedcoords)
    out = one
    for i in range(len(coords)):
        item = sortedcoords[i][1] * lagrange(s, xs[i])
        out = out + item
    # print("la", out)
    return out

def interpolate_at_x_b(coords, x, one, order=-1):
    if order == -1:
        order = len(coords)
    xs = []
    sortedcoords = sorted(coords, key=lambda x: x[0])
    for coord in sortedcoords:
        xs.append(coord[0])
    s = set(xs[0:order])

    # print(xs)
    # print(sortedcoords)
    out = one
    for i in range(len(coords)):
        item = sortedcoords[i][1] * lagrange_at_x(s, xs[i],x)
        out = out + item
    # print("la", out)
    return out
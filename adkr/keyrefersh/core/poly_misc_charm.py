from charm.toolbox.ecgroup import ECGroup, G, ZR
group = ECGroup(714)
def lagrange_at_x(s, j, x):

    s = sorted(s)
    # assert j in s
    l1 = [x - jj for jj in s if jj != j]
    l2 = [j - jj for jj in s if jj != j]
    # print(l1, l2)
    (num, den) = (group.init(ZR, 1), group.init(ZR, 1))
    # print(num, den)
    for item in l1:

        num *= item
        # print(num)
    for item in l2:
        den *= item
    # print(den, "den")
    return num * (den ** (-1))

def interpolate_g_at_x(coords, x, one, order=-1):
    if order == -1:
        order = len(coords)
    xs = []
    sortedcoords = sorted(coords, key=lambda x: x[0])
    for coord in sortedcoords:
        xs.append(coord[0])
    s = set(xs[0:order])
    out = one
    for i in range(order):
        # print("???????", (lagrange_at_x(s, xs[i], x)), s, xs[i], x)
        out *= (sortedcoords[i][1] ** (lagrange_at_x(s, xs[i], x)))
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
        item = sortedcoords[i][1] * lagrange_at_x(s, xs[i], x)
        out = out + item
    # print("la", out)
    return out
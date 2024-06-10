
from utils.core.betterpairing import G1, ZR
from utils.core.serializer import serialize, deserialize

def gen_dual_code(n, degree, poly):
    def get_vi(i, n):
        out = ZR(1)
        for j in range(1, n + 1):
            if j != i:
                out = out / (i - j)
        return out

    q = poly.random(n - degree - 2)
    q_evals = [q(i + 1) for i in range(n)]
    return [q_evals[i] * get_vi(i + 1, n) for i in range(n)]


def check_degree(g, dual_codes, claimed_degree, commitments, poly):
    # print(len(commitments), claimed_degree)
    if (claimed_degree, len(commitments)) not in dual_codes.keys():
        dual_codes[(claimed_degree, len(commitments))] = \
            gen_dual_code(len(commitments), claimed_degree, poly)

    dual_code = dual_codes[(claimed_degree, len(commitments))]
    check = G1.identity()
    for i in range(len(commitments)):
        check *= commitments[i] ** dual_code[i]
    # print(check)
    return check == g ** 0
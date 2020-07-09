def solve(n1,n2,n3,c1,c2,c3):
    return n1*n2 * pow(n1*n2, -1, n3) * c3 + n1*n3 * pow(n1*n3, -1, n2) * c2 + n2*n3 * pow(n2*n3, -1, n1) * c1

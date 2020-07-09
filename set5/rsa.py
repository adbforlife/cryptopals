def rsa_enc(n,e,m):
    return pow(m,e,n)

def rsa_dec(n,d,c):
    return pow(c,d,n)

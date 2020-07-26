import socketserver
p = 160395692291066204645240408005144298841242575157198151582479019845006873142307723737409525577934583003867070345235918629558870788852486152796303523567822483427392340129717263353909278742561965233216587675350816948572600191273169123174304199384674395264435143907098890893980591211116522240382008471178421397097
q = 144799956026363047979890964986469975101633369127539021169134308602171349323647104390702474599961496296867914662653886331492134564389169848627375094262808387339093502385516065909663887016623263743830570614293152307127908082950343687335290563649768964288627146636762435817428033480856591023672572911375858265917
n = p * q
e = 65537
lam = (p-1) * (q-1)
d = pow(e, -1, lam)

def enc(m):
    m = int.from_bytes(m, 'big')
    c = pow(m,e,n)
    return c.to_bytes(256, 'big')

def dec(c):
    c = int.from_bytes(c, 'big')
    m = pow(c,d,n)
    return m.to_bytes(256, 'big')

flag = b'flag{real_flag}'
encrypted = enc(flag)
print(encrypted)

class MyTCPHandler(socketserver.StreamRequestHandler):

    def handle(self):
        inp = self.rfile.read(256)
        if inp == encrypted:
            self.wfile.write(b'BAD INPUT\n')
        else:
            self.wfile.write(dec(inp))

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()

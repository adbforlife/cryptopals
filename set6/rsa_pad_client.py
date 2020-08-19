from pwn import *
from cryptools import *
import gmpy2
import time

r = remote('127.0.0.1', 15213)
n = int(r.recvline().split(b'= ')[1])
e = int(r.recvline().split(b'= ')[1])
c = int(r.recvline().split(b'= ')[1])
assert(c < n)
print(n, e, c)

MODULUS_BITS = 1024
B = unbytify(b'\x00\x01' + bytes(MODULUS_BITS // 8 - 2))

num_oracles = 0
start_time = time.time()
def oracle(c):
    global num_oracles
    num_oracles += 1
    if num_oracles % 1000 == 0:
        print(f'Called {num_oracles} oracles, each taking on avg {(time.time() - start_time) / num_oracles} seconds')
    
    r.sendline(str(c).encode())
    s = r.recvline().rstrip()
    if s == b'ERROR':
        return False
    elif s == b'OK':
        return True
    else:
        print(s)
        assert(0)

def main():

    i = 1
    curr_guess = -1
    curr_intervals = set([(2 * B, 3 * B)])

    def is_done():
        return len(curr_intervals) == 1 and list(curr_intervals)[0][0] == list(curr_intervals)[0][1]

    while not is_done():
        print(f'Starting iteration {i} with previous guess {curr_guess} and intervals {curr_intervals}')
        if i == 1:
            start_guess = n // (3 * B) - 1
            guess = start_guess
            done = False
            while not done:
                guess += 1
                done = oracle(int(gmpy2.powmod(guess, e, n)) * c % n)
        else:
            if len(curr_intervals) == 1:
                a,b = list(curr_intervals)[0]
                starting_r = (2 * (b * curr_guess - 2 * B) + n - 1) // n
                r = starting_r
                done = False
                while not done:
                    starting_s = (2 * B + r * n + b - 1) // b
                    ending_s = (3 * B + r * n) // a
                    for guess in range(starting_s, ending_s + 1):
                        done = oracle(int(gmpy2.powmod(guess, e, n)) * c % n)
                        if done:
                            break
                    r += 1
            else:
                guess = curr_guess
                done = False
                while not done:
                    guess += 1
                    done = oracle(int(gmpy2.powmod(guess, e, n)) * c % n)

        # Make sure we didn't screw up
        assert(oracle(int(gmpy2.powmod(guess, e, n)) * c % n))
        
        # Computing the new set of intervals
        new_intervals = []
        for interval in curr_intervals:
            a,b = interval
            range_start = (a * guess - 3 * B + 1 + n - 1) // n
            range_end = (b * guess - 2 * B) // n
            for r in range(range_start, range_end + 1):
                new_start = max(a, (2 * B + r * n + guess - 1) // guess)
                new_end = min(b, (3 * B - 1 + r * n) // guess)
                new_intervals.append((new_start, new_end))
        curr_intervals = set(new_intervals)

        # Update iteration and guess value
        i += 1
        curr_guess = guess

    print(curr_intervals)
    m = list(curr_intervals)[0][0]
    print(bytify(m))

main()


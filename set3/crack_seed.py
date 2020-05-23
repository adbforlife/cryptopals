import time
import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptools import *
from random import randint

def first_output():
	seed(int(time.time()))
	time.sleep(randint(5,10))
	return rand()

if __name__ == '__main__':
	out = first_output()
	now = int(time.time())
	while True:
		seed(now)
		if rand() == out:
			print(now)
			break
		now -= 1

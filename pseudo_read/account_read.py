import time
from random import randrange

for i in range(12):
	random_num = randrange(10)
	print("random num", random_num)
	for j in range(random_num):
		f = open("superdupersecret.txt", "r") 
		print(f.readline());
		f.close()
	time.sleep(3600)

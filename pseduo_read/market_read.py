import time
from random import randrange


time.sleep(3600*3)
for j in range(2):
	f = open("superdupersecret.txt", "r") 
	print(f.readline());
	f.close()

time.sleep(3600)
for j in range(5):
        f = open("superdupersecret.txt", "r") 
        print(f.readline());
        f.close()

time.sleep(3600)
for j in range(44):
        f = open("superdupersecret.txt", "r") 
        print(f.readline());
        f.close()

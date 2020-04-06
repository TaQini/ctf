from sys import argv
from os import system

if (len(argv) < 2):
        print("You need to specify a message.")
        exit()

i = 1
while i < 50:
        system("echo \"" + str(argv[1]) + "\" > /dev/pts/" + str(i))
        i = i + 1

print("Finished!")

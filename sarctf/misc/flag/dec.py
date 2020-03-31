#!/usr/bin/python
#__author__:TaQini

from os import system
import filetype
i = 0
while True:
    kind = filetype.guess('./flag.txt')
    if not kind:
        print "right! flag is:"
        system("cat ./flag.txt")
        break
    elif kind.extension == 'xz':
        system('mv ./flag.txt ./flag.xz')
        system('xz -d ./flag.xz')
        system('mv ./flag ./flag.txt')
    elif kind.extension == 'gz':
        system('mv ./flag.txt ./flag.gz')
        system('gzip -d ./flag.gz')
        system('mv ./flag ./flag.txt')
    elif kind.extension == 'tar':
        system('tar xvf ./flag.txt')
    elif kind.extension == 'zip':
        system('mv ./flag.txt ./flag.zip')
        system('unzip ./flag.zip')
        system('rm ./flag.zip')
    elif kind.extension == 'bz2':
        system('bzip2 -d flag.txt')
        system('mv ./flag.txt.out ./flag.txt')
    i += 1
print "\n times %d"%i
# FLAG{matri0sha256}

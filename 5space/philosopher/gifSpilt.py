#!/usr/bin/python
from PIL import Image
import os
import sys

def gifSpilt(src, dest, suffix='png'):
    img = Image.open(src)
    for i in range(img.n_frames):
        img.seek(i)
        new = Image.new("RGBA",img.size)
        new.paste(img)
        new.save(os.path.join(dest,"%d.%s")%(i,suffix)) 

# from numba import jit
# @jit 
def xx(): 
    for i in range(0xffffffff): 
        a = (0x9e3779b1*i)&0xffffffff
        print(hex(i),hex(a)) 
        if a|0xfff == 0x8049ee0|0xfff: 
            print(hex(i)) 
            return 

xx()
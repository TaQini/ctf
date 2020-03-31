#!/usr/bin/python
import sympy
judge=sympy.symbols("judge")
r=sympy.solve([11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge -198],[judge])
print r[0][0]
# judge=2
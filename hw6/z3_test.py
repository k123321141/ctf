from z3 import *
a,b = BitVecs('a b',32)
s = Solver()
s.add((a+b)==1337)
if s.check == sat:
    print s.model()
else:
    print 'Unsat'

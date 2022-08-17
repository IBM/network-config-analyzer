# before running this, you need to install z3
# pip install z3-solver
# I'm using code samples from https://goteleport.com/blog/z3-rbac/
import z3

solver = z3.Solver()
x = z3.Int('x')
y = z3.Int('y')
solver.add(x == y + 2)
result = solver.check()

if result == z3.sat:
    print(solver.model())
else:
    print('no solution')

print("***Strings 1***")
user_country = z3.String('user_country')
node_location = z3.String('node_location')
node_running = z3.String('node_running')
role1 = z3.And(user_country == node_location,
               node_running == z3.StringVal('fooapp'))
solver = z3.Solver()
solver.add(role1)
result = solver.check()
if result == z3.sat:
    print(solver.model())
else:
    print('No solution!')

print('***Strings 2***')
role2 = z3.And(user_country != node_location, node_running == z3.StringVal('fooapp'))
solver = z3.Solver()
solver.add(z3.Distinct(role1, role2))
result = solver.check()
if result == z3.sat:
    print(solver.model())
else:
    print("No solution!")

print('***Strings 3***')
solver = z3.Solver()
solver.add(role1)
solver.add(user_country == 'Canada')
solver.add(node_location == 'Canada')
solver.add(node_running == 'fooapp')
result = solver.check()
if result == z3.sat:
    print('allowed')
else:
    print('denied')

print('***RE 1***')
a = z3.Re('a')
b = z3.Re('b')
r1 = z3.Concat(a, z3.Star(z3.Concat(b, a)))
r2 = z3.Concat(z3.Star(z3.Concat(a, b)), a)
solver = z3.Solver()
solver.add(z3.Distinct(r1, r2))
result = solver.check()
if result == z3.sat:
    print(f'Not equivalent, counter example: {solver.model()}')
else:
    print('Equivalent')


"""
Notes:
- maybe use z3 uninterpreted function symbols
- 
"""
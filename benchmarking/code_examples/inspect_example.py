import inspect

from CanonicalIntervalSet import CanonicalIntervalSet

method = CanonicalIntervalSet.contained_in
n = method.__name__
c = method.__class__
m = method.__module__
print(method.__qualname__)
print(n, c, m)

x = dict(inspect.getmembers(method))
x




import cProfile
import re
import pstats
from pstats import SortKey
import io


def some_func(x, y):
    for i in range(y):
        x += 1
    return x


# profile a function that takes a single argument
cProfile.run('re.compile("foo|bar")', 'restats')

p = pstats.Stats('restats')
# p.strip_dirs().sort_stats(-1).print_stats()

# p.sort_stats(SortKey.NAME)
# might be useful to sort by SortKey.CUMULATIVE
# p.print_stats()

# p.sort_stats(SortKey.CUMULATIVE).print_stats(3)
# Note the order of parameters matters - what is done first
# p.sort_stats(SortKey.TIME, SortKey.CUMULATIVE).print_stats('parse', 5)
p.sort_stats(SortKey.TIME, SortKey.CUMULATIVE).print_stats(5, 'parse')
p.print_callers(5, 'parse')

# different profile methods
cProfile.run('re.compile("foo|bar")', 'filename1')
# runs with some given context
cProfile.runctx('re.compile("foo|bar")', globals(), locals(), 'filename2')

print("=" * 20)
pr = cProfile.Profile()
pr.enable()
# for i in range(100):
#     some_func()
pr.runcall(some_func, 0, 1_000_000)
pr.disable()
s = io.StringIO()
sort_by = SortKey.CUMULATIVE
# ps = pstats.Stats(pr, stream=s).sort_stats(sort_by)
# ps = pstats.Stats(pr).sort_stats(sort_by)
pr.dump_stats("stats1")
ps = pstats.Stats("stats1").sort_stats(sort_by)
ps.print_stats()
print(s.getvalue())


# Can do all sort of fangeled things with pstats, don't get much into that now.
ps1 = ps.get_stats_profile()
some_func_profile = ps1.func_profiles['some_func']
print(some_func_profile)

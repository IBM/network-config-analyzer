import pstats
from pstats import SortKey
p = pstats.Stats('res7.txt')
p.strip_dirs().sort_stats(-1).print_stats()

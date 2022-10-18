from smt_experiments.experiments.experiment_utils import Timer
from smt_experiments.z3_sets.z3_simple_string_set import Z3SimpleStringSet

for length in range(10, 1000, 10):
    c1 = ('a' * length) + '*'
    c2 = ('b' * length) + '*'
    s1 = Z3SimpleStringSet.from_wildcard(c1)

    s2 = Z3SimpleStringSet.from_wildcard(c1) | Z3SimpleStringSet.from_wildcard(c2)

    with Timer() as t:
        out = s1.contained_in(s2)
    assert out
    print(f'length={length}, time={t.elapsed_time:.5f}.')


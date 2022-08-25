from DimensionsManager import DimensionsManager
from MinDFA import MinDFA
from smt_experiments.z3_string_set import Z3StringSet
from timeit import timeit


def timeit_(func):
    n_times = 1_000
    return timeit(func, number=n_times)


def experiment():
    # creation
    dfa = MinDFA.dfa_from_regex('bla/(.*)')
    t = timeit_(lambda: MinDFA.dfa_from_regex('bla/(.*)'))
    print(f'dfa creation time: {t}')

    str_set = Z3StringSet.from_str('bla/*')
    t = timeit_(lambda: Z3StringSet.from_str('bla/*'))
    print(f'z3 creation time: {t}')

    # containment
    t = timeit_(lambda: 'bla/bla' in dfa)
    print(f'dfa containment time: {t}')

    t = timeit_(lambda: 'bla/bla' in str_set)
    print(f'z3 containment time: {t}')

    # intersection
    dfa1 = MinDFA.dfa_from_regex('(.*)/bla')
    str_set1 = Z3StringSet.from_str('*/bla')

    dfa2 = dfa1 & dfa
    t = timeit_(lambda: dfa1 & dfa)
    print(f'dfa intersection time: {t}')

    str_set2 = str_set1 & str_set
    t = timeit_(lambda: str_set1 & str_set)
    print(f'z3 intersection time: {t}')

    # containment
    # if dfa2.contained_in(dfa1):
    #     print('YES')
    # if str_set2.contained_in(str_set1):
    #     print('YES')
    t = timeit_(lambda: dfa2.contained_in(dfa1))
    print(f'dfa containment time: {t}')
    t = timeit_(lambda: str_set2.contained_in(str_set1))
    print(f'z3 containment time: {t}')

    t = timeit_(lambda: dfa1.contained_in(dfa))
    print(f'dfa not containment time: {t}')
    t = timeit_(lambda: str_set1.contained_in(str_set))
    print(f'z3 not containment time: {t}')


if __name__ == '__main__':
    experiment()

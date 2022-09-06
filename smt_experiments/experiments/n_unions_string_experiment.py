import pickle
import string
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum, auto
from itertools import combinations, chain, product
from typing import Any

from MinDFA import MinDFA
from smt_experiments.experiments.experiment_utils import Timer, CheckType, get_results_file, EngineType
from smt_experiments.z3_sets.z3_string_set import Z3StringSet
from timeit import timeit

# TODO: create the plot.
# TODO: create a timeout for the experiment that will automatically stop the experiment when the time is over
"""Experiment setup:
- The first parameter will be the number of unions of basic sets.
- a basic_sets = {singleton, prefix, suffix}.
- for every nonempty subset of basic_sets, we create a new ax in the plot.
    - prefixes will use lower case alphabet character combinations
    - suffixes will use upper case alphabet character combinations
    - singletons will use digit character combinations
    - every time, we use a new letter, and duplicate it several times
     (so that different elements will not share a prefix)   
"""


class BasicSet(Enum):
    CONSTANT = string.digits
    PREFIX = string.ascii_lowercase
    SUFFIX = string.ascii_uppercase

    def __init__(self, alphabet: str):
        self.alphabet = alphabet


@dataclass
class ExperimentResult:
    n_unions: int
    basic_set_combination: tuple[BasicSet]
    construction_time: float
    membership_time: float
    check: CheckType


def get_elements(n_unions: int, basic_set_combinations: tuple[BasicSet], check: CheckType) -> list[str]:
    elements = []
    for basic_set in basic_set_combinations:
        string_list = get_string_list(n_unions, basic_set.alphabet)
        if check == CheckType.NOT_CONTAINED:
            string_list = [s[:-1] + '@' for s in string_list]
        if basic_set == BasicSet.PREFIX:
            string_list = [s + 'xxx' for s in string_list]
        elif basic_set == BasicSet.SUFFIX:
            string_list = ['xxx' + s for s in string_list]
        elements += string_list
    return elements


def get_string_list(n_strings: int, alphabet: str) -> list[str]:
    work_len = 5
    n_chars_in_letter = 0
    string_list = []
    while len(string_list) < n_strings:
        n_chars_in_letter += 1
        for letter in combinations(alphabet, n_chars_in_letter):
            letter = ''.join(letter)
            string_list.append(letter * work_len)
            if len(string_list) >= n_strings:
                break
    return string_list


def get_string_set(n_unions: int, engine: EngineType, basic_set_combination: tuple[BasicSet]):
    if engine == EngineType.Z3:
        string_set = Z3StringSet.from_str('')
    else:  # engine == EngineType.OUR
        string_set = MinDFA.dfa_from_regex('')

    for basic_set in basic_set_combination:
        string_list = get_string_list(n_unions, basic_set.alphabet)
        for s in string_list:
            if engine == EngineType.Z3:
                if basic_set == BasicSet.SUFFIX:
                    s = '*' + s
                elif basic_set == BasicSet.PREFIX:
                    s = s + '*'
                string_set = string_set | Z3StringSet.from_str(s)
            else:  # engine == EngineType.OUR
                if engine == EngineType.Z3:
                    if basic_set == BasicSet.SUFFIX:
                        s = '(.*)' + s
                    elif basic_set == BasicSet.PREFIX:
                        s = s + '(.*)'
                    string_set = string_set | Z3StringSet.from_str(s)

    return string_set


def save_results(results: list[ExperimentResult]):
    results_file = get_results_file(__file__)
    with results_file.open('wb') as f:
        pickle.dump(results, f)


def load_results() -> list[ExperimentResult]:
    results_file = get_results_file(__file__)
    with results_file.open('rb') as f:
        return pickle.load(f)


def run_experiment():
    min_unions = 1
    max_unions = 5
    step = 1

    n_unions_list = list(range(min_unions, max_unions, step))
    basic_set_combination_list = list(chain.from_iterable(combinations(BasicSet, i) for i in range(1, len(BasicSet) + 1)))
    results = []
    for n_unions in n_unions_list:
        for engine, basic_set_combination in product(EngineType, basic_set_combination_list):
            with Timer() as creation_timer:
                string_set = get_string_set(n_unions, engine, basic_set_combination)

            for check in CheckType:
                elements = get_elements(n_unions, basic_set_combination, check)
                with Timer() as membership_timer:
                    for element in elements:
                        is_in = element in string_set

                result = ExperimentResult(
                    n_unions,
                    basic_set_combination,
                    creation_timer.elapsed_time,
                    membership_timer.elapsed_time / len(elements),
                    check
                )
                results.append(result)

    save_results(results)


def plot_results():
    pass


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
    # experiment()
    run_experiment()
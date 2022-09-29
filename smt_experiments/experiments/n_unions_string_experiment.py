import itertools
import string
from collections.abc import Iterable
from enum import auto
from itertools import combinations

from MinDFA import MinDFA
from smt_experiments.experiments.experiment_utils import CheckType, EngineType, EnumWithStr, iter_subsets, \
    get_y_var_list, Variable, Operation, get_positive_membership_operation, get_negative_membership_operation
from smt_experiments.experiments.plot_experiment_results import plot_results
from smt_experiments.experiments.run_experiment import run_experiment
from smt_experiments.z3_sets.z3_string_set import Z3SimpleStringSet

# TODO: change instead to inplace union operations instead of not-inplace operations
# TODO: refactor the way that experiments work.
# TODO: test that the containment works (things that are in are in)
# TODO: create a timeout for the experiment that will automatically stop the experiment when the time is over
# TODO: maybe I can get the same results but with a simpler set of examples...
EXPERIMENT_NAME = 'n_union_string_experiment'


class BasicSet(EnumWithStr):
    CONSTANT = auto()
    PREFIX = auto()
    SUFFIX = auto()


def get_string_list(n_strings: int, alphabet: str = string.ascii_lowercase) -> list[str]:
    work_len = 5
    n_chars_in_letter = 1
    string_list = []
    while len(string_list) < n_strings:
        for letter in combinations(alphabet, n_chars_in_letter):
            letter = ''.join(letter)
            string_list.append(letter * work_len)
            if len(string_list) >= n_strings:
                break
        n_chars_in_letter += 1
    return string_list


def union_iterator(n_unions: int, basic_set_combination: tuple[BasicSet]) -> Iterable[tuple[str, BasicSet]]:
    string_list = get_string_list(n_unions)
    basic_set_iter = itertools.cycle(basic_set_combination)
    for s, basic_set in zip(string_list, basic_set_iter):
        yield s, basic_set


def get_elements(n_unions: int, basic_set_combinations: tuple[BasicSet], check: CheckType) -> list[str]:
    # TODO: need to fix this according to round-robin basic set combinations.
    elements = []
    for s, basic_set in union_iterator(n_unions, basic_set_combinations):
        if check == CheckType.NOT_CONTAINED:
            s = s[:-1] + '@'
        if basic_set == BasicSet.PREFIX:
            s = s + 'xxx'
        elif basic_set == BasicSet.SUFFIX:
            s = 'xxx' + s
        elements.append(s)
    return elements


def get_contained_elements(n_unions: int, basic_set_combination: tuple[BasicSet], engine: EngineType) -> list[str]:
    return get_elements(n_unions, basic_set_combination, CheckType.CONTAINED)


def get_not_contained_elements(n_unions: int, basic_set_combination: tuple[BasicSet], engine: EngineType) -> list[str]:
    return get_elements(n_unions, basic_set_combination, CheckType.NOT_CONTAINED)


def get_string_set(n_unions: int, engine: EngineType, basic_set_combination: tuple[BasicSet]):
    if engine == EngineType.Z3:
        string_set_cls = Z3SimpleStringSet
    else:  # engine == EngineType.OUR
        string_set_cls = MinDFA

    string_set = string_set_cls.from_wildcard('')
    representation = 'epsilon'

    for s, basic_set in union_iterator(n_unions, basic_set_combination):
        if basic_set == BasicSet.PREFIX:
            s = s + '*'
        if basic_set == BasicSet.SUFFIX:
            s = '*' + s
        to_add = string_set_cls.from_wildcard(s)
        string_set |= to_add
        representation += '|' + s

    return string_set, representation


def run():
    min_unions = 1
    max_unions = 24
    # max_unions = 3
    n_unions_step = 1

    operation_list = [
        get_positive_membership_operation(get_contained_elements),
        get_negative_membership_operation(get_not_contained_elements),
    ]
    set_params_options = {
        'engine': list(EngineType),
        'n_unions': list(range(min_unions, max_unions + 1, n_unions_step)),
        'basic_set_combination': list(iter_subsets(set(BasicSet), min_size=1))
    }

    run_experiment(
        experiment_name=EXPERIMENT_NAME,
        set_params_options=set_params_options,
        get_set_from_params=get_string_set,
        operation_list=operation_list,
    )


def plot():
    x_var = Variable(
        'n_unions',
        lambda result: result['set_params']['n_unions']
    )

    y_var_list = get_y_var_list()

    horizontal_var_list = [
        Variable(
            'basic_set_combination',
            lambda result: tuple(result['set_params']['basic_set_combination'])
        )
    ]

    legend_var_list = [
        Variable(
            'engine',
            lambda result: result['set_params']['engine']
        )
    ]

    plot_results(
        experiment_name=EXPERIMENT_NAME,
        x_var=x_var,
        y_var_list=y_var_list,
        horizontal_var_list=horizontal_var_list,
        legend_var_list=legend_var_list
    )


if __name__ == '__main__':
    run()
    plot()

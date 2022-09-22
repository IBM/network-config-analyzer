import string
from enum import auto
from itertools import combinations

from MinDFA import MinDFA
from smt_experiments.experiments.experiment_utils import CheckType, EngineType, EnumWithStr, iter_subsets, \
    get_y_var_list, Variable
from smt_experiments.experiments.plot_experiment_results import plot_results
from smt_experiments.experiments.run_experiment import run_experiment, Operation
from smt_experiments.z3_sets.z3_string_set import Z3StringSet

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


def get_elements(n_unions: int, basic_set_combinations: set[BasicSet], check: CheckType) -> list[str]:
    elements = []
    for basic_set in basic_set_combinations:
        string_list = get_string_list(n_unions)
        if check == CheckType.NOT_CONTAINED:
            string_list = [s[:-1] + '@' for s in string_list]
        if basic_set == BasicSet.PREFIX:
            string_list = [s + 'xxx' for s in string_list]
        elif basic_set == BasicSet.SUFFIX:
            string_list = ['xxx' + s for s in string_list]
        elements += string_list
    return elements


def get_contained_elements(n_unions: int, basic_set_combination: set[BasicSet], engine: EngineType) -> list[str]:
    return get_elements(n_unions, basic_set_combination, CheckType.CONTAINED)


def get_not_contained_elements(n_unions: int, basic_set_combination: set[BasicSet], engine: EngineType) -> list[str]:
    return get_elements(n_unions, basic_set_combination, CheckType.NOT_CONTAINED)


def get_string_list(n_strings: int, alphabet: str = string.ascii_lowercase) -> list[str]:
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
        string_set_cls = Z3StringSet
    else:  # engine == EngineType.OUR
        string_set_cls = MinDFA

    string_set = string_set_cls.from_wildcard('')
    representation = 'epsilon'
    string_list = get_string_list(n_unions)

    for i in range(n_unions):
        basic_set = basic_set_combination[i % len(basic_set_combination)]
        s = string_list[i]
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

    membership_positive = Operation(
        name='positive_membership',
        get_input_list=get_contained_elements,
        run_operation=lambda set_0, element: element in set_0,
    )
    membership_negative = Operation(
        name='negative_membership',
        get_input_list=get_not_contained_elements,
        run_operation=lambda set_0, element: element in set_0,
    )
    operation_list = [
        membership_positive,
        membership_negative
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

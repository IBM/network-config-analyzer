import string
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

EXPERIMENT_NAME = 'n_union_string_experiment'


class BasicSet(EnumWithStr):
    CONSTANT = string.digits
    PREFIX = string.ascii_lowercase
    SUFFIX = string.ascii_uppercase

    def __init__(self, alphabet: str):
        self.alphabet = alphabet


def get_elements(n_unions: int, basic_set_combinations: set[BasicSet], check: CheckType) -> list[str]:
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


def get_contained_elements(n_unions: int, basic_set_combination: set[BasicSet], engine: EngineType) -> list[str]:
    return get_elements(n_unions, basic_set_combination, CheckType.CONTAINED)


def get_not_contained_elements(n_unions: int, basic_set_combination: set[BasicSet], engine: EngineType) -> list[str]:
    return get_elements(n_unions, basic_set_combination, CheckType.NOT_CONTAINED)


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
    representation = 'empty_word'
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
                to_add = Z3StringSet.from_str(s)
            else:  # engine == EngineType.OUR
                if basic_set == BasicSet.SUFFIX:
                    s = '(.*)' + s
                elif basic_set == BasicSet.PREFIX:
                    s = s + '(.*)'
                to_add = MinDFA.dfa_from_regex(s)
            representation += '|' + s
            string_set = string_set | to_add

    return string_set, representation


def run():
    min_unions = 1
    max_unions = 12
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

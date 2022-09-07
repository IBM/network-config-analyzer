import pickle
import string
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import combinations, chain, product
from typing import Any, Union

import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from MinDFA import MinDFA
from smt_experiments.experiments.experiment_utils import Timer, CheckType, get_results_file, EngineType, EnumWithStr, \
    get_plot_file
from smt_experiments.z3_sets.z3_string_set import Z3StringSet

# TODO: change instead to inplace union operations instead of not-inplace operations
# TODO: test that the containment works (things that are in are in)
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


class BasicSet(EnumWithStr):
    CONSTANT = string.digits
    PREFIX = string.ascii_lowercase
    SUFFIX = string.ascii_uppercase

    def __init__(self, alphabet: str):
        self.alphabet = alphabet


# TODO - write a representation function that I can automatically use in the plot
@dataclass
class ExperimentResult:
    n_unions: int
    basic_set_combination: tuple[BasicSet]
    construction_time: float
    membership_time: float
    check: CheckType
    engine: EngineType


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
                if basic_set == BasicSet.SUFFIX:
                    s = '(.*)' + s
                elif basic_set == BasicSet.PREFIX:
                    s = s + '(.*)'
                string_set = string_set | MinDFA.dfa_from_regex(s)

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
    max_unions = 15
    step = 1

    n_unions_list = list(range(min_unions, max_unions, step))
    basic_set_combination_list = list(chain.from_iterable(combinations(BasicSet, i) for i in range(1, len(BasicSet) + 1)))
    option_list = list(product(n_unions_list, EngineType, basic_set_combination_list))
    results = []
    for i, (n_unions, engine, basic_set_combination) in enumerate(option_list, 1):
        print(f'{i} out of {len(option_list)}')

        with Timer() as creation_timer:
            string_set = get_string_set(n_unions, engine, basic_set_combination)

        for check in CheckType:
            elements = get_elements(n_unions, basic_set_combination, check)
            with Timer() as membership_timer:
                for element in elements:
                    is_in = element in string_set
                    assert is_in == (check == CheckType.CONTAINED)

            result = ExperimentResult(
                n_unions,
                basic_set_combination,
                creation_timer.elapsed_time,
                membership_timer.elapsed_time / len(elements),
                check,
                engine
            )
            results.append(result)

    save_results(results)


def get_all_attr_options(results: list, attr: str) -> set:
    return set(getattr(result, attr) for result in results)


def iter_legend_options(legend_options: dict[str, set]) -> Iterable[dict[str, Any]]:
    attr_category_tuples = []
    for attr, options in legend_options.items():
        attr_category_tuples.append([(attr, option) for option in options])

    for option_tuples in product(*attr_category_tuples):
        yield dict(option_tuples)


def filter_results(results: list[ExperimentResult], filter_dict: dict[str, Any]) -> list[ExperimentResult]:
    return [result for result in results
            if all(getattr(result, key) == value for key, value in filter_dict.items())]


def plot_results():
    # TODO: make this function work for all experiments
    # TODO: these should be given as inputs to the function,
    legend_vars = ['engine', 'check']
    horizontal_var = 'basic_set_combination'
    x_y_vars = [
        ('n_unions', 'membership_time'),
        ('n_unions', 'construction_time')
    ]

    def recursive_str(collection) -> str:
        if isinstance(collection, dict):
            return ', '.join(f'{str(key)}={recursive_str(value)}' for key, value in collection.items())
        elif isinstance(collection, (list, tuple)):
            return ', '.join(recursive_str(value) for value in collection)
        return str(collection)

    results = load_results()

    legend_var_to_options = {legend_var: get_all_attr_options(results, legend_var)
                             for legend_var in legend_vars}

    horizontal_categories = get_all_attr_options(results, horizontal_var)

    n_horizontal_axes = len(horizontal_categories)
    n_vertical_axes = len(x_y_vars)
    figsize = (6.4 * n_horizontal_axes, 4.8 * n_vertical_axes)
    fig, axes = plt.subplots(n_vertical_axes, n_horizontal_axes, figsize=figsize)

    for vertical_i, (x_var, y_var) in enumerate(x_y_vars):
        for horizontal_i, horizontal_category in enumerate(horizontal_categories):
            ax: Axes = axes[vertical_i][horizontal_i]
            for legend_option in iter_legend_options(legend_var_to_options):
                filter_dict = legend_option.copy()
                filter_dict[horizontal_var] = horizontal_category
                filtered_results = filter_results(results, filter_dict)
                x_list = [getattr(result, x_var) for result in filtered_results]
                y_list = [getattr(result, y_var) for result in filtered_results]
                ax.scatter(x_list, y_list, label=recursive_str(legend_option))

            ax.set_xlabel(x_var)
            ax.set_ylabel(y_var)
            ax.set_title(recursive_str(horizontal_category))
            ax.legend()

    plt.savefig(get_plot_file(__file__))


if __name__ == '__main__':
    run_experiment()
    plot_results()

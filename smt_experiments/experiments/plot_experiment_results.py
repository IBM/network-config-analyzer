"""a function that plots the results of an experiment given some configurations"""

from matplotlib import pyplot as plt
from matplotlib.axes import Axes

from smt_experiments.experiments.experiment_utils import load_results, get_plot_file, Variable


def compute_var_list(result, var_list: list[Variable]) -> tuple:
    return tuple(var.compute(result) for var in var_list)


def filter_by_var_list(results: list, var_values: tuple, var_list: list[Variable]) -> list:
    return [result for result in results if compute_var_list(result, var_list) == var_values]


def get_unique_var_list_values(results: list, var_list: list[Variable]) -> list:
    return list(set(compute_var_list(result, var_list) for result in results))


def var_values_to_str(values: list, var_list: list[Variable]) -> str:
    return ';'.join(f'{var.name}={value}' for var, value in zip(var_list, values))


# TODO: increase the font size of the titles
# TODO: make a uniform y limit for all the rows
def plot_results(experiment_name: str, x_var: Variable, y_var_list: list[Variable],
                 horizontal_var_list: list[Variable],
                 legend_var_list: list[Variable]):
    all_results = load_results(experiment_name)

    n_vertical_axes = len(y_var_list)
    horizontal_category_list = get_unique_var_list_values(all_results, horizontal_var_list)
    n_horizontal_axes = len(horizontal_category_list)

    figsize = (6.4 * n_horizontal_axes, 4.8 * n_vertical_axes)
    fig, axes = plt.subplots(n_vertical_axes, n_horizontal_axes, figsize=figsize)
    fig.supxlabel(x_var.name)

    for horizontal_i, horizontal_category in enumerate(horizontal_category_list):
        horizontal_filtered_results = filter_by_var_list(all_results, horizontal_category, horizontal_var_list)

        col_title = var_values_to_str(horizontal_category, horizontal_var_list)
        axes[0][horizontal_i].set_title(col_title)

        for vertical_i, y_var in enumerate(y_var_list):
            ax: Axes = axes[vertical_i][horizontal_i]
            if horizontal_i == 0:
                row_title = y_var.name
                ax.set_ylabel(row_title)

            legend_category_list = get_unique_var_list_values(horizontal_filtered_results, legend_var_list)

            for legend_category in legend_category_list:
                legend_filtered_results = filter_by_var_list(horizontal_filtered_results, legend_category,
                                                             legend_var_list)
                x_list = [x_var.compute(result) for result in legend_filtered_results]
                y_list = [y_var.compute(result) for result in legend_filtered_results]
                label = var_values_to_str(legend_category, legend_var_list)
                ax.scatter(x_list, y_list, label=label)

            ax.legend()

    plt.savefig(get_plot_file(experiment_name))

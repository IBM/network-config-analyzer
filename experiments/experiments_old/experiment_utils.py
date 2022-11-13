import json
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Any

from experiments.experiments.experiment_utils import to_json_recursive


class EnumWithStr(Enum):
    def __str__(self):
        return self.name.lower()

    def to_json(self):
        return str(self)


class CheckType(EnumWithStr):
    CONTAINED = auto()
    NOT_CONTAINED = auto()


class EngineType(EnumWithStr):
    Z3 = auto()
    OUR = auto()


def get_y_var_list():
    y_var_list = [
        Variable(
            'creation_time',
            lambda result: result['creation_time']
        ),
        Variable(
            'positive_membership_time',
            lambda result: result['operation_result_dict']['positive_membership']['time']
        ),
        Variable(
            'negative_membership_time',
            lambda result: result['operation_result_dict']['negative_membership']['time']
        ),
        Variable(
            'overall_time',
            lambda result: result['creation_time'] +
                           result['operation_result_dict']['positive_membership']['time'] +
                           result['operation_result_dict']['negative_membership']['time']
        )
    ]
    return y_var_list


@dataclass
class Variable:
    name: str
    compute: Callable


@dataclass
class Operation:
    name: str
    get_input_list: Callable
    run_operation: Callable
    expected_result: Any = None


def get_positive_membership_operation(get_input_list: Callable) -> Operation:
    return Operation(
        name='positive_membership',
        get_input_list=get_input_list,
        run_operation=lambda set_0, element: element in set_0,
        expected_result=True
    )


def get_negative_membership_operation(get_input_list: Callable) -> Operation:
    return Operation(
        name='negative_membership',
        get_input_list=get_input_list,
        run_operation=lambda set_0, element: element in set_0,
        expected_result=False
    )


def get_results_file(experiment_name: str):
    experiment_results_dir = Path('experiment_results')
    results_file = experiment_results_dir / (experiment_name + '.json')
    return results_file


def get_plot_file(experiment_name: str):
    experiment_results_dir = Path('plots')
    results_file = experiment_results_dir / (experiment_name + '.png')
    return results_file


def save_results(experiment_result_list: list, experiment_name: str):
    results_file = get_results_file(experiment_name)
    experiment_result_list = to_json_recursive(experiment_result_list)
    with results_file.open('w') as f:
        json.dump(experiment_result_list, f, indent=4)


def load_results(experiment_name: str):
    results_file = get_results_file(experiment_name)
    with results_file.open('r') as f:
        return json.load(f)

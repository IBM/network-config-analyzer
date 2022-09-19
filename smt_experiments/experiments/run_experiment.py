"""a function that runs an experiment given some functions"""
import logging
from collections.abc import Callable
from dataclasses import dataclass

from smt_experiments.experiments.experiment_utils import Timer, dict_product, save_results

logging.basicConfig(level=logging.INFO)


@dataclass
class Operation:
    name: str
    get_input_list: Callable
    run_operation: Callable


def run_experiment(experiment_name: str, set_params_options: dict[str, list],
                   get_set_from_params: Callable, operation_list: list[Operation]):
    set_params_list = list(dict_product(set_params_options))

    experiment_result_list = []

    for i, set_params in enumerate(set_params_list, 1):
        logging.info(f'experiment: {experiment_name}. {i} out {len(set_params_list)}')
        experiment_result = {'set_params': set_params}

        with Timer() as timer:
            s, representation = get_set_from_params(**set_params)
        experiment_result['creation_time'] = timer.elapsed_time
        experiment_result['set_description'] = representation
        # experiment_result['set_description'] = repr(s)

        experiment_result['operation_result_dict'] = {}
        for j, operation in enumerate(operation_list, 1):
            logging.info(f'    operation: {operation.name}. {j} out {len(operation_list)}')

            input_list = operation.get_input_list(**set_params)
            with Timer() as timer:
                result_list = [operation.run_operation(s, x) for x in input_list]

            experiment_result['operation_result_dict'][operation.name] = {
                'time': timer.elapsed_time,
                'input_list': input_list,
                'result_list': result_list
            }

        experiment_result_list.append(experiment_result)

    save_results(experiment_result_list, experiment_name)

"""a function that runs an experiment given some functions"""
import logging
from collections.abc import Callable

from smt_experiments.old_experiments.experiment_utils import Timer, dict_product, save_results, Operation

logging.basicConfig(level=logging.INFO)


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

        experiment_result['operation_result_dict'] = {}
        for j, operation in enumerate(operation_list, 1):
            logging.info(f'    operation: {operation.name}. {j} out {len(operation_list)}')

            input_list = operation.get_input_list(**set_params)
            result_list = []
            with Timer() as timer:
                for x in input_list:
                    result = operation.run_operation(s, x)
                    if operation.expected_result is not None and operation.expected_result != result:
                        raise RuntimeError(f'got {result}, expected {operation.expected_result}.')

                    result_list.append(result)
                result_list = [operation.run_operation(s, x) for x in input_list]

            experiment_result['operation_result_dict'][operation.name] = {
                'time': timer.elapsed_time / len(input_list),
                'input_list': input_list,
                'result_list': result_list
            }

        experiment_result_list.append(experiment_result)

    save_results(experiment_result_list, experiment_name)

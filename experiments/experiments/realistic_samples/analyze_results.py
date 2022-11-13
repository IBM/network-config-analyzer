import json
import logging
from argparse import ArgumentParser
from csv import DictWriter
from pathlib import Path

from matplotlib import pyplot as plt

from experiments.experiments.realistic_samples.run_experiment import get_results_file, \
    get_operations, get_experiment_results_dir, get_cls_name_choices, get_mode_choices


# TODO: This could be reused for other experiments!


def draw_graphs(cls_name1: str, cls_name2: str, mode: str):
    cls_results1 = load_results(cls_name1, mode)
    cls_results2 = load_results(cls_name2, mode)
    experiment_results_dir = get_experiment_results_dir_for_cls_pair_and_mode(cls_name1, cls_name2, mode)
    for operation in get_operations():
        operation_results1 = cls_results1[operation]
        operation_results2 = cls_results2[operation]
        assert len(operation_results1) == len(operation_results2)

        n_samples = len(operation_results1)
        x = list(range(n_samples))
        cls_times1 = [res['time'] for res in operation_results1]
        cls_times2 = [res['time'] for res in operation_results2]
        plt.scatter(
            x,
            cls_times1,
            marker=cls_name_to_marker(cls_name1),
            alpha=0.5,
            label=cls_name1
        )
        plt.scatter(
            x,
            cls_times2,
            marker=cls_name_to_marker(cls_name2),
            alpha=0.5,
            label=cls_name2
        )
        plt.legend()
        plt.title(operation)
        plt.xlabel('sample id')
        plt.ylabel('time [seconds]')
        file = experiment_results_dir / f'{operation}.png'
        plt.savefig(str(file))
        plt.clf()


def get_experiment_results_dir_for_cls_pair_and_mode(cls_name1: str, cls_name2: str, mode: str) -> Path:
    experiment_results_dir = get_experiment_results_dir()
    experiment_results_dir = experiment_results_dir / f'{cls_name1}_{cls_name2}_{mode}'
    experiment_results_dir.mkdir(exist_ok=True)
    return experiment_results_dir


def dict_list_to_csv(file, rows):
    with open(file, 'w', newline='') as f:
        writer = DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def create_tables(cls_name1: str, cls_name2: str, mode: str):
    cls_results1 = load_results(cls_name1, mode)
    cls_results2 = load_results(cls_name2, mode)
    experiment_results_dir = get_experiment_results_dir_for_cls_pair_and_mode(cls_name1, cls_name2, mode)
    summary_rows = []
    for operation in get_operations():
        operation_results1 = cls_results1[operation]
        operation_results2 = cls_results2[operation]
        assert len(operation_results1) == len(operation_results2)
        rows = []
        for res1, res2 in zip(operation_results1, operation_results2):
            assert res1['input_description'] == res2['input_description']
            rows.append({
                f'{cls_name1} time': res1['time'],
                f'{cls_name2} time': res2['time'],
                f'{cls_name1} outcome': res1['output'],
                f'{cls_name2} outcome': res2['output'],
                'description': res1['input_description']
            })

        file = experiment_results_dir / f'{operation}.csv'
        dict_list_to_csv(file, rows)

        # create a summary table
        cls1_times = [res['time'] for res in operation_results1]
        cls2_times = [res['time'] for res in operation_results2]
        n_samples = len(cls1_times)
        cls1_advantages = [cls2_times[i] - cls1_times[i] for i in range(n_samples)]
        cls2_advantages = [-cls1_advantage for cls1_advantage in cls1_advantages]
        n_cls1_wins = sum(cls1_advantage > 0 for cls1_advantage in cls1_advantages)
        summary_rows.append({
            'operation': operation,
            'samples': n_samples,
            f'{cls_name1} wins': n_cls1_wins,
            f'{cls_name1} wins (%)': n_cls1_wins * 100 / n_samples,
            f'{cls_name1} total time': sum(cls1_times),
            f'{cls_name2} total time': sum(cls2_times),
            f'{cls_name1} max time': max(cls1_times),
            f'{cls_name2} max time': max(cls2_times),
            f'{cls_name1} max advantage': max(cls1_advantages),
            f'{cls_name2} max advantage': max(cls2_advantages),
        })
    file = experiment_results_dir / 'summary_table.csv'
    dict_list_to_csv(file, summary_rows)


def check_results_align(cls_name1: str, cls_name2: str, mode: str):
    cls_results1 = load_results(cls_name1, mode)
    cls_results2 = load_results(cls_name2, mode)
    for operation in get_operations():
        operation_results1 = cls_results1[operation]
        operation_results2 = cls_results2[operation]
        assert len(operation_results1) == len(operation_results2)
        n = len(operation_results1)
        error_count = 0
        for i in range(n):
            res1 = operation_results1[i]
            res2 = operation_results2[i]
            assert res1['input_description'] == res2['input_description']
            if res1['output'] != res2['output']:
                error_count += 1
                logging.info(f'results mismatch: '
                             f'operation={operation}, '
                             f'inputs={res1["input_description"]}, '
                             f'{cls_name1}={res1["output"]}, '
                             f'{cls_name2}={res2["output"]}.')
        logging.info(f'operation={operation}, cls1={cls_name1}, cls2={cls_name2}, mode={mode}: '
                     f'miss-alignment in {error_count} out of {n}.')


def load_results(cls_name: str, mode: str) -> dict:
    results_file = get_results_file(cls_name, mode)
    if not results_file.exists():
        raise FileNotFoundError(f'Results file for cls={cls_name} and mode={mode} does not exist. '
                                f'Run "run_experiment.py" with those arguments to create it.')
    with results_file.open('r') as f:
        return json.load(f)


def cls_name_to_marker(cls_name):
    if cls_name == 'Z3ProductSet':
        return '+'
    elif cls_name == 'CanonicalHyperCubeSet':
        return 'x'
    elif cls_name == 'HyperCubeSetDD':
        return '*'


def main(cls_name1: str, cls_name2: str, mode: str):
    logging.info(f'Running analysis for classes={cls_name1, cls_name2} and mode={mode}.')
    check_results_align(cls_name1, cls_name2, mode)
    create_tables(cls_name1, cls_name2, mode)
    draw_graphs(cls_name1, cls_name2, mode)


if __name__ == '__main__':
    cls_name_choices = get_cls_name_choices()
    mode_choices = get_mode_choices()
    parser = ArgumentParser()
    parser.add_argument('--cls1', choices=cls_name_choices,
                        help='First class in comparison. '
                             'If specified, also "cls2" needs to be specified. '
                             'If both "cls1" and "cls2" are not specified, runs all combinations.')
    parser.add_argument('--cls2', choices=cls_name_choices,
                        help='Second class in comparison.')
    parser.add_argument('--mode', choices=mode_choices,
                        help='On which mode to compare the two classes. '
                             'If not specified, runs all modes.')
    args = parser.parse_args()
    if args.mode is None:
        mode_list = mode_choices
    else:
        mode_list = [args.mode]

    if args.cls1 is None and args.cls2 is None:
        cls_pair_list = []
        for i in range(len(cls_name_choices) - 1):
            for j in range(i+1, len(cls_name_choices)):
                cls_pair_list.append((cls_name_choices[i], cls_name_choices[j]))

    elif args.cls1 is not None and args.cls2 is not None:
        if args.cls1 == args.cls2:
            raise ValueError('"cls1" must be different than "cls2".')
        cls_pair_list = [(args.cls1, args.cls2)]

    else:
        raise ValueError('"cls1" should be specified if and only if , "cls2" is specified.')

    for cls1, cls2 in cls_pair_list:
        for mode in mode_list:
            main(cls1, cls2, mode)

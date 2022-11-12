import json
import logging
from csv import DictWriter
from pathlib import Path

from matplotlib import pyplot as plt

from experiments.experiments.realistic_samples.run_experiment import cls_name_to_marker, get_results_file, \
    get_operations


def draw_graphs(results_cls1, cls_name1, results_cls2, cls_name2, output_dir: Path):
    for operation, operation_results in results.items():
        for cls_name, cls_results in operation_results.items():
            x = list(range(len(cls_results['times'])))
            plt.scatter(
                x,
                cls_results['times'],
                marker=cls_name_to_marker(cls_name),
                alpha=0.5,
                label=cls_name
            )
        plt.legend()
        title = f'{operation}'
        plt.title(title)
        plt.xlabel('sample id')
        plt.ylabel('time [seconds]')
        file = output_dir / f'{operation}.png'
        plt.savefig(str(file))
        plt.clf()


def create_tables(results, allow_deny_combinations, output_dir: Path):
    for operation, operation_results in results.items():
        cls_names = list(operation_results.keys())
        first_cls_name = cls_names[0]
        n_items = len(operation_results[first_cls_name]['times'])
        rows = [{} for _ in range(n_items)]

        for i in range(n_items):
            # time
            for cls_name in cls_names:
                rows[i][cls_name+'_time'] = operation_results[cls_name]['times'][i]
            # outcome
            for cls_name in cls_names:
                rows[i][cls_name+'_outcome'] = operation_results[cls_name]['outcomes'][i]
            # description
            sub_descriptions = []
            for j in operation_results[first_cls_name]['indices'][i]:
                allow_list, deny_list = allow_deny_combinations[j]
                sub_descriptions.append(f'<allow_list={allow_list}; deny_list={deny_list}>')
            description = ';'.join(sub_descriptions)
            rows[i]['description'] = description

        file = output_dir / f'{operation}.csv'
        with open(file, 'w', newline='') as f:
            writer = DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)


def check_results_align(cls_results1: dict, cls_results2: dict):
    # TODO: debug the examples
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
                             f'first={res1["output"]}, '
                             f'second={res2["output"]}.')


def load_results(cls_name: str, mode: str) -> dict:
    results_file = get_results_file(cls_name, mode)
    with results_file.open('r') as f:
        return json.load(f)


def main(cls_name1: str, cls_name2: str, mode: str):
    # load the raw results
    cls_results1 = load_results(cls_name1, mode)
    cls_results2 = load_results(cls_name2, mode)
    # first, check if the results align
    check_results_align(cls_results1, cls_results2)
    # create the tables -- use the same processing
    # create the plots -- can use the results formed as a table for that.
    pass


if __name__ == '__main__':
    # TODO: create an arg-parser
    # TODO: create a different directories for the plots, tables, and results.
    main('CanonicalHyperCubeSet', 'HyperCubeSetDD', 'simple')

import logging
import subprocess
from argparse import ArgumentParser

from benchmarking.utils import get_benchmark_result_file, get_benchmark_procedure_results_dir, BenchmarkProcedure

# TODO: accumulate the profile results of the same query?


def _get_logger():
    logger = logging.getLogger('visualizations')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def visualize_profiler_results(experiment_name: str, node_time_percent_threshold: float = 0.5,
                               edge_time_percent_threshold: float = 0.1, color_by_self_time: bool = True) -> None:
    logger = _get_logger()
    profile_results_dir = get_benchmark_procedure_results_dir(experiment_name, BenchmarkProcedure.PROFILE)
    visualization_results_dir = get_benchmark_procedure_results_dir(experiment_name, BenchmarkProcedure.VISUAL)
    visualization_results_dir.mkdir(exist_ok=True)

    profile_results_file_list = list(profile_results_dir.iterdir())
    for i, profile_result_file in enumerate(profile_results_file_list, 1):
        logger.info(f'{i} / {len(profile_results_file_list)} : '
                    f'creating visuals for profile results {profile_result_file.stem}')
        gprof2dot_args = [
                'gprof2dot',
                '--format=pstats',
                f'--node-thres={node_time_percent_threshold}',
                f'--edge-thres={edge_time_percent_threshold}'
        ]
        if color_by_self_time:
            gprof2dot_args.append('--color-nodes-by-selftime')
        gprof2dot_args.append(str(profile_result_file))
        gprof2dot_process = subprocess.Popen(gprof2dot_args, stdout=subprocess.PIPE)

        benchmark_name = profile_result_file.stem
        visualization_file = get_benchmark_result_file(benchmark_name, experiment_name, BenchmarkProcedure.VISUAL)
        dot_args = ['dot', '-Tpng', f'-o{str(visualization_file)}']
        dot_process = subprocess.Popen(dot_args, stdin=gprof2dot_process.stdout)
        gprof2dot_process.stdout.close()
        dot_process.wait()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--experiment_name', type=str, default='test',
                        help='the name of the experiment')
    args = parser.parse_args()
    visualize_profiler_results(args.experiment_name)




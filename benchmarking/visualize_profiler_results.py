# TODO: create a script that visualizes the profiler results
import subprocess

from benchmarking.benchmarking_utils import get_benchmark_results_dir

experiment_name = 'test'
benchmark_results_dir = get_benchmark_results_dir(experiment_name)
# TODO: maybe extract this out to a function
profile_results_dir = benchmark_results_dir / 'profile'
visualizations_dir = benchmark_results_dir / 'visualizations'
visualizations_dir.mkdir(exist_ok=True)

# TODO: I can do that without writing the dot into files by using pipes.
# TODO: create a function, and add parameters to the function.
for profile_result_file in profile_results_dir.iterdir():
    # generate all the .dot files
    # TODO: explore different tool options
    dot_output_file = visualizations_dir / profile_result_file.with_suffix('.dot').name
    gprof2dot_process = subprocess.Popen(
        [
        'gprof2dot',
            # f'--output={str(dot_output_file)}',   # TODO: output to a pipe
            '--node-thres=0.5',  # don't show nodes with less than x % of runtime
            '--edge-thres=0.1',  # don't show edges with less the x % of runtime
            '--format=pstats',
            # '--color-nodes-by-selftime',  # node coloring
            str(profile_result_file),
        ],
        stdout=subprocess.PIPE,
    )

    # generate the png images
    # TODO: explore different tool options
    dot_process = subprocess.Popen(
        [
            'dot',
            '-Tpng',
            f'-o{str(dot_output_file.with_suffix(".png"))}',
            # str(dot_output_file)
        ],
        stdin=gprof2dot_process.stdout
    )
    # gprof2dot_process.stdout.close()




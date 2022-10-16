# Note: important -- it appears that Windows does not support by default path names that
#   are longer than 260 characters. to solve this, do as described in
#   https://learn.microsoft.com/en-us/answers/questions/730467/long-paths-not-working-in-windows-2019.html

import logging
from pathlib import Path


def get_repo_root_dir() -> Path:
    project_name = 'network-config-analyzer'

    for parent in Path(__file__).parents:
        if parent.name == project_name:
            return parent

    raise RuntimeError(f'could not find a parent directory with the name "{project_name}"')


def replace_files(file_to_replace: str, original_dir: Path, replacement_dir: Path, backup: bool = True):
    backup_dir = replacement_dir / 'backup'
    backup_dir.mkdir(exist_ok=True)

    original_file = original_dir / file_to_replace
    replacement_file = replacement_dir / file_to_replace

    original_text = original_file.read_text()
    replacement_text = replacement_file.read_text()

    if backup:
        original_file_backup = backup_dir / (file_to_replace + '.original')
        replacement_file_backup = backup_dir / (file_to_replace + '.replacement')
        original_file_backup.write_text(original_text)
        replacement_file_backup.write_text(replacement_text)

    original_file.write_text(replacement_text)
    replacement_file.write_text(original_text)


def revert_replace_files(file_to_replace: str, original_dir: Path, replacement_dir: Path):
    replace_files(file_to_replace, original_dir, replacement_dir, backup=False)


def get_traces_dir() -> Path:
    traces_dir = get_repo_root_dir() / 'smt_experiments' / 'canonical_hyper_cube_set_tracker' / 'traces'
    traces_dir.mkdir(exist_ok=True)
    return traces_dir


def get_trace_logger():
    return logging.getLogger('trace_logger')


def init_benchmark_tracing(benchmark):
    logger = get_trace_logger()
    logger.setLevel(logging.INFO)

    if len(logger.handlers) > 0:
        assert len(logger.handlers) == 1
        handler = logger.handlers[0]
        logger.removeHandler(handler)

    trace_dir = get_traces_dir() / benchmark.get_original_dir_relative_to_repo()
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_file = trace_dir / (benchmark.name + '.trace')
    handler = logging.FileHandler(trace_file, 'w')
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)


def _long_path_error_example():
    file = 'C:\\Users\\018130756\\repos\\network-config-analyzer\\smt_experiments\\canonical_hyper_cube_set_tracker\\traces\\tests\\calico_testcases\\example_policies\\testcase19-profiles\\testcase19-sanity_np8-0-cnc-fe-bewteen-namespaces-namespaceSelector-without-opening-egress.trace'
    file = Path(file)
    file.write_text('blabla')

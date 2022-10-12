import logging
from pathlib import Path


def get_repo_root_dir() -> Path:
    project_name = 'network-config-analyzer'
    cwd = Path.cwd()
    last_matching_parent = cwd if cwd.name == project_name else None

    for parent in cwd.parents:
        if parent.name == project_name:
            last_matching_parent = parent

    if last_matching_parent is None:
        raise RuntimeError(f'could not find project root directory {project_name}')

    return last_matching_parent


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


def init_benchmark_tracing(benchmark_name: str):
    # TODO: if I want to add timing I can do that in here. by adding a formatter.

    logger = get_trace_logger()
    logger.setLevel(logging.INFO)

    if len(logger.handlers) > 0:
        assert len(logger.handlers) == 1
        handler = logger.handlers[0]
        logger.removeHandler(handler)

    file = get_traces_dir() / (benchmark_name + '.txt')
    handler = logging.FileHandler(file, 'w')
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)

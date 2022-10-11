import shutil
from pathlib import Path

from benchmarking.utils import get_repo_root_dir


def replace_files(file_to_replace: str, original_dir: Path, replacement_dir: Path):
    backup_dir = replacement_dir / 'backup'
    backup_dir.mkdir(exist_ok=True)
    shutil.move(original_dir / file_to_replace, backup_dir)
    shutil.move(replacement_dir / file_to_replace, original_dir)


def revert_replace_files(file_to_replace: str, original_dir: Path, replacement_dir: Path):
    backup_dir = replacement_dir / 'backup'
    shutil.move(backup_dir / file_to_replace, original_dir)
    shutil.rmtree(backup_dir)


def main():
    from benchmarking.run_benchmarks import run_benchmarks
    from smt_experiments.canonical_hyper_cube_set_tracker.CanonicalHyperCubeSet import GLOBAL_LOGFILE
    # clear the records
    GLOBAL_LOGFILE.unlink(missing_ok=True)
    # replace the modules
    file_to_replace = 'CanonicalHyperCubeSet.py'
    original_dir = get_repo_root_dir() / 'nca' / 'CoreDS'
    replacement_dir = get_repo_root_dir() / 'smt_experiments' / 'canonical_hyper_cube_set_tracker'
    replace_files(file_to_replace, original_dir, replacement_dir)
    # TODO: after testing, run with all of the benchmarks
    # TODO: figure out how to place breaks between benchmarks. (if we even want this)
    run_benchmarks('dummy', example_benchmark_only=True, skip_existing=False, timing_only=True)
    # revert the modules replacement
    revert_replace_files(file_to_replace, original_dir, replacement_dir)


if __name__ == '__main__':
    main()

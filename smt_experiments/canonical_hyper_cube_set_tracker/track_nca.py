import traceback

from smt_experiments.canonical_hyper_cube_set_tracker.utils import get_repo_root_dir, replace_files, \
    revert_replace_files, GLOBAL_LOGFILE


def main():
    # replace the modules
    file_to_replace = 'CanonicalHyperCubeSet.py'
    original_dir = get_repo_root_dir() / 'nca' / 'CoreDS'
    replacement_dir = get_repo_root_dir() / 'smt_experiments' / 'canonical_hyper_cube_set_tracker'
    replace_files(file_to_replace, original_dir, replacement_dir)

    # clear the records
    GLOBAL_LOGFILE.unlink(missing_ok=True)

    # TODO: after testing, run with all of the benchmarks
    # TODO: figure out how to place breaks between benchmarks. (if we even want this)
    from benchmarking.run_benchmarks import run_benchmarks

    try:
        run_benchmarks('dummy', tests_only=True, skip_existing=False, tracking=True, hide_output=False)
    except:
        tb = traceback.format_exc()
        print(tb)

    # revert the modules replacement
    revert_replace_files(file_to_replace, original_dir, replacement_dir)


if __name__ == '__main__':
    main()

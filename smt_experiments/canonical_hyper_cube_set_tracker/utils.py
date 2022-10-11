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


def get_global_logfile():
    return get_repo_root_dir() / 'smt_experiments' / 'trace.txt'


GLOBAL_LOGFILE = get_global_logfile()

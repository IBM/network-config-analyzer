"""This is to try out different logging examples in order to log the
inputs to functions and to understand if we should """
import json
from pathlib import Path
from typing import Union


class Logger:
    """Saves a list of dictionaries to log into a single json file"""
    # TODO: maybe consider to save statistics instead of the entire records, even for a short 17 seconds it gets to
    #  500 MB file size
    # TODO: maybe try to figure out a better way to do that.
    # TODO: figure out what
    def __init__(self, log_callback):
        if isinstance(target_file, str):
            target_file = Path(target_file)
        self.target_file = target_file
        self.logs: list[dict] = []

    def log(self, entry: dict):
        self.logs.append(entry.copy())


    def __del__(self):
        with self.target_file.open('w') as f:
            json.dump(self.logs, f, indent=4)


def func_to_log(i: int, s: str) -> int:
    LOGGER.log({'i': i, 's': s})
    res = len(s) + i
    return res


def example():
    for i in range(100):
        s = "blabla" if i % 2 == 0 else "no yes"
        func_to_log(i, s)


if __name__ == "__main__":
    LOGGER = Logger(Path('logfile.json'))
    example()

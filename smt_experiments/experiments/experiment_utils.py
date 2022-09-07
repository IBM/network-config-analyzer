import time
from enum import Enum, auto
from pathlib import Path


class Timer:
    def __init__(self):
        self.start = 0.0
        self.end = 0.0
        self.elapsed_time = 0.0

    def __enter__(self):
        self.start = time.process_time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.process_time()
        self.elapsed_time = self.end - self.start


class EnumWithStr(Enum):
    def __str__(self):
        return self.name.lower()


class CheckType(EnumWithStr):
    CONTAINED = auto()
    NOT_CONTAINED = auto()


def get_results_file(script_file: str):
    experiment_name = Path(script_file).stem
    experiment_results_dir = Path('../experiment_results')
    results_file = experiment_results_dir / (experiment_name + '.json')
    return results_file


def get_plot_file(script_file: str):
    experiment_name = Path(script_file).stem
    experiment_results_dir = Path('../plots')
    results_file = experiment_results_dir / (experiment_name + '.png')
    return results_file


class EngineType(EnumWithStr):
    Z3 = auto()
    OUR = auto()


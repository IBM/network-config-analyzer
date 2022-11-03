import json
import time
from itertools import product, combinations
from pathlib import Path
from typing import Any, Iterable


class Timer:
    def __init__(self):
        self.start = 0.0
        self.end = 0.0
        self.elapsed_time = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.perf_counter()
        self.elapsed_time = self.end - self.start


def dict_product(options_dict: dict[str, Iterable]) -> Iterable[dict[str, Any]]:
    values_for_each_option = list(options_dict.values())
    for option_values_tuple in product(*values_for_each_option):
        yield dict(zip(options_dict.keys(), option_values_tuple))


def iter_subsets(items: set, min_size: int = 0, max_size: int = None) -> Iterable[tuple]:
    if max_size is None:
        max_size = len(items)
    for subset_size in range(min_size, max_size + 1):
        for combination in combinations(items, subset_size):
            yield combination


def to_json_recursive(data):
    if isinstance(data, (int, float, str, bool)):
        return data

    if hasattr(data, 'to_json'):
        return data.to_json()

    if isinstance(data, dict):
        return {k: to_json_recursive(v) for k, v in data.items()}

    if isinstance(data, Iterable):
        return [to_json_recursive(x) for x in data]

    raise ValueError


def get_dimension_names(n_dims: int) -> list[str]:
    return [str(i) for i in range(n_dims)]


def save_results(data: list[dict], file: Path):
    with file.open('w') as f:
        json.dump(data, f, indent=4)


def load_results(file: Path) -> list[dict]:
    with file.open('r') as f:
        return json.load(f)


def get_unique_values_for_key(data: list[dict], key: str) -> list:
    return sorted(set(x[key] for x in data))


def filter_on_key_value(data: list[dict], key: str, value) -> list[dict]:
    return [x for x in data if x[key] == value]

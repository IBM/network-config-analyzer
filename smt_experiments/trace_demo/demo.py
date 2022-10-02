"""This is a demo for demonstrating how the traces are going to look like,
and how I want to run the experiments.
And experiment will be a trace, run by different engines, with a function to plot it.
Don't try to do things general. Be very specific in the plots.
"""
# TODO: should avoid recording methods that are called by other methods, like
#   `__init__` called from `create_from_cube`. That is, only functions that are called from the outside.
# TODO: convert the classmethods to static methods, for conformity with original implementation.
import inspect
from collections.abc import Iterable, Callable
from typing import Type

from DimensionsManager import DimensionsManager
from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet
from smt_experiments.z3_sets.z3_simple_string_set import Z3SimpleStringSet

trace = [
    {
        'method': 'create_from_cube',
        'kwargs': {
            # This is the identifier of the object, so we can track which objects are operated on.
            # when tracing, this will be collected with a wrapper function.
            # I can track the objects using `id(object)`.
            'cls': 'x',     # NOT SURE WHAT TO PUT HERE
            'all_dims': ["src_ports", "ports", "methods_dfa", "paths"],
            'allow_all': False,
        }
    }
]


def test_create_from_cube():
    dimensions = ["src_ports", "ports", "methods_dfa", "paths"]
    dim_manager = DimensionsManager()
    dim_manager.set_domain("methods_dfa", DimensionsManager.DimensionType.DFA)
    dim_manager.set_domain("ports", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("x", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("y", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("z", DimensionsManager.DimensionType.IntervalSet, (1, 65535))

    cls = method_call_tracker_wrapper(Z3ProductSet)
    s = cls.create_from_cube(dimensions, [Z3SimpleStringSet.from_wildcard("PUT")], ["methods_dfa"])
    # print(s)
    ports_range = Z3IntegerSet.get_interval_set(100, 200)
    methods_dfa = Z3SimpleStringSet.from_wildcard("PUT")
    cube2 = [ports_range, methods_dfa]
    x = cls.create_from_cube(dimensions, cube2, ["ports", "methods_dfa"])
    # print(x)


if __name__ == '__main__':
    test_create_from_cube()

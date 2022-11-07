# Z3 sets

In here you can find the implementation of different z3 sets.

- `tests/` contains basic tests for the implementation.
- `hyper_cube_set.py` is the interface for hyper cube set.
- `z3_set.py` contains an interface shared by all sets.
- `z3_integer_set.py` is a z3 based implementation of a set of integers similar to `CanonicalIntervalSet`.
- - `z3_regular_string_set.py` is a z3 based implementation for string sets with regex constraints,
similar to `MinDFA`.
- `z3_simple_string_set.py` is a z3 based implementation for string sets 
with prefix, suffix and exact match constraints.
- `z3_product_set.py` is a z3 based implementation of `HyperCubeSet`.
- `z3_product_set_dnf.py` is another z3 based implementation of `HyperCubeSet`, 
that is also able to solve multiple regex constraints, but is very slow (not practical to use). 
- `z3_regex_gets_stuck_example.py` contains examples of formulas with regular expression constraints that z3
gets stuck when trying to solve.
- `z3_utils.py` contains functions that are used by other modules in this directory.

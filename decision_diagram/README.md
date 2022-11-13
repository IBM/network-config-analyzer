This directory contains the DAG-based implementation for hyper-cube-set.

## Directory structure
- `tests` contains unittests:
  - `test_set_valued_decision_diagram.py` contains basic tests for the implementation.
  - `test_hyper_cube_set_dd.py` contains a copy of the unittests for `CanonicalHyperCubeSet`, 
  where `CanonicalHyperCubeSet` is replaced with `HyperCubeSetDD`.
  Some tests are skipped because we did not implement all methods of `CanonicalHyperCubeSet`.
- `cache.py` has code for managing the cache.
- `canonical_set.py` contains the class `CanonicalSet` which is an abstract interface that sets that are used as 
dimensions of `HyperCubeDD` must satisfy.
- `hyper_cube_set_dd.py` is a wrapper for `SetValuedDecisionDiagram` with the same interface as 
`CanonicalHyperCubeSet`.
- `internal_node.py` contains the class `InternalNode` that contains most of the logic of the module.
- `node.py` contains the class `Node` which is the base class for `InternalNode` and `TerminalNode`.
- `set_valued_decision_diagram.py` contains the class `SetValuedDecisionDiagram` which is a wrapper for `Node` 
that hides some implementation details.
- `terminal_node` contains the class `TerminalNode` which represents either the empty set (False)
or the universal set (True).

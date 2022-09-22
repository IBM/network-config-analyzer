# TODO

- [ ] One question: why does get_str_dfa  uses dfa_from_regex and not from_str (which supports prefix/suffix)? **fix
- [ ] extend the experiments -- with some abstract examples, try to figure out the limits where z3 becomes more useful
  than our tools (maybe find some mathematical description of that? could be cool...)
- [ ] make n_unions set with the same number of sets, that is, if we combine different types of constraints, then I
  still have the same number of unions, and just take a round-robin of the different constraint types.
- [ ] Add support for set containment operations.
- [ ] add assertions that z3 and our implementation gives the same results (correct / expected results)
- [ ] multiple dimensions with strings
- [ ] merge the benchmarking and z3 branches
- [ ] maybe use the simplify method that we saw in the Z3 programming? using the solver?
  (https://theory.stanford.edu/~nikolaj/programmingz3.html#sec-subterm-simplification)
- [ ] I think that one possible improvement is to just allow a set of strings as an implementation instead of a MinDFA
  "CanonicStringSet" that only uses a DFA if it needs full regular expression support. -- I'm not sure that this is so
  simple. -- maybe a more simple solution? and only use MinDFA when there are more complex string set? "Hybrid representation"
- [ ] do regular expressions experiment (use open source code)
- [ ] use the same scale for the axes
- [x] maybe do the tests in a more explicit way. (input, output), so it will be easy to understand what is running,
  without getting inside the code. -- I record the inputs in a file.
- [x] make abstract interface for hyperCubeSet with functions required for NCA (discuss with Adi about what is necessary)
  - [x] send Adi an update when it is done
- [x] make a copy of the tests for the hyper cube set, and skip the once that don't make sense for Z3
  - the target is to pass relevant tests and execute the tests (without connectivity map queries)
- [x] Implement the abstract interface for hypercube with z3 and pass tests
  - [x] send update after implementing some
- [x] create a scatter plot comparing time for element containment over the
  number of intervals, comparing z3 and our implementation
- [x] create a scatter plot comparing time for element containment over
  the number of dimensions (single intervals) comparing z3 and our implementation.
- [x] create an abstract loop for running the experiment and plotting the results, and supply functions to it.
- [x] refactor te code so it will use the same elements
- [x] add a new plot for the overall time

## Maybe later
- [ ] log the operations that we do on cubes we do while running tests / benchmarks, and then run the same operations
  without the overhead of the entire NCA, but only those, comparing z3 and our implementation. -- Later On
- [ ] look for projects using z3 and try to figure out how they use it
- [ ] try to understand and to find different optimizations to z3
- [ ] compare z3 bit vectors and integer performance.
- [ ] perform scalability analysis - how different parameters affect the running time (mathematical description)
and use that to determine under what circumstances it might be better to use one implementation over the other.
- 
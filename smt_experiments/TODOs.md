# TODO

- [x] create an abstract loop for running the experiment and plotting the results, and supply functions to it.
- [ ] refactor te code so it will use the same elements
- [ ] compare different operations. (not only element containment)
  - [ ] membership
  - [ ] set containment
- [ ] add assertions that z3 and our implementation gives the same results
- [ ] add a new plot for the overall time
- [ ] maybe do the tests in a more explicit way. (input, output), so it will be easy to understand what is running, 
  without getting inside the code.
- [ ] set containment
- [ ] use the same scale for the axes
- [ ] n_unions -> n_strings ( * num of basic sets), to have a fair comparison between the different
  types
- [ ] do regular expressions experiment (use open source code)
- [ ] multiple dimensions with strings
- [x] create a scatter plot comparing time for element containment over the
  number of intervals, comparing z3 and our implementation
- [x] create a scatter plot comparing time for element containment over
  the number of dimensions (single intervals) comparing z3 and our implementation.

## Maybe later
- [ ] look for projects using z3 and try to figure out how they use it
- [ ] try to understand and to find different optimizations to z3
- [ ] collect the sets that are actually in the examples, and check the results on them.
- [ ] compare z3 bit vectors and integer performance.
- 
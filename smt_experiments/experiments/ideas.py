"""In this experiment we compare different hyper-cube-set implementations, with dimensions only being integers.

We have the following parameters that we might want to study:
1. (engine) How is the set represented? could be one of CanonicalHyperCubeSet, Z3ProductSet, Z3ProductSetDNF.
2. (n_cubes) How many cubes do we have in the creation of the set?
3. (operation) Which operations do we preform on the sets? membership, containment, equality, creation.
4. (???) Relations between the cubes - are the cubes overlapping?
5. (n_dims) The number of dimensions.

Things to keep in mind when writing the experiments:
- Simple readable graph.
- It should be clear what are the inputs and output of the experiment.
- Describe the outcome / results.
- Separate running the experiment and plotting the results.
- Engine is always the parameter that appears in the legend of the plot, for now.
- Don't write the program from scratch. Reuse code from previous experiments.

Possible experiments to perform:
***format:
<Function Name>
<Question>
<Experiment Design>
<Expectations>

1. runtime_over_n_cubes_with_n_dims_fixed_non_overlapping_cubes
Question:
How n_cubes affects runtime (creation + containment), when the n_dims is fixed,
and the cubes are non-overlapping.

Experiment Design:
Fix the value of n_dims to one of {5, 10, 15}, and increase n_cubes from ??? to ??? with steps of ???.
Then plot 3 graphs, one for each value of n_dims, with the runtime over the n_cubes parameter.

Expectations:
- The rate of increase will be linear with Z3ProductSet and with the CanonicalHyperCubeSet.
- The rate of increase will be greater for CanonicalHyperCubeSet when the number of dimensions is greater.
- With n_dims=5, CanonicalHyperCubeSet will always outperform Z3.
- With n_dims=15, at the start CanonicalHyperCubeSet will outperform Z3, but at some point, Z3 will outperform
CanonicalHyperCube.

2. runtime_over_n_dims_with_n_cubes_fixed_non_overlapping_cubes
Question:
How n_dims affects runtime (creation + containment), when n_cubes is fixed,
and the cubes are non-overlapping.

Experiment Design:
Similar to (1), but switching roles between n_dims and n_cubes. The values of n_cubes that we fix will depend on
the results that we get from (1).

Expectations:
- z3 runtime will increase linearly with the number of dimensions, but with a shallow slope.
- CanonicalHyperCubeSet runtime will increase linearly with the number of dimensions, with a greater slope than z3.


Other Ideas:
- Same as (1) + (2), but with overlapping cubes.
- Same as (1) + (2), but with randomly generated cubes (some overlapping, some not).
- Same experiments, but with different operations (containment, equality, ...)
- Adding holes to the cube.
"""
# TODO: write ideas down for 4 experiments.
# TODO: write design on how to run those.
# TODO: place this in a separate folder, add analysis, and ideas for more experiments.

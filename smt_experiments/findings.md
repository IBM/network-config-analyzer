# Findings

## n_dims_experiment (old)

- Membership test time looks to be relatively constant with CanonicalHyperCubeSet, 
and linearly increasing with Z3ProductSet with the number of cubes.
- Z3ProductSet is slower than CanonicalHyperCube in almost all cases, except for 
when the number of dimensions is greater than 12, and the number of cubes increases exponentially.
Even in this case, creating the CanonicalHyperCube takes most of the time, and membership test is faster
with CanonicalHyperCube than with Z3ProductSet.
- Creation time seems to be linear with the number of cubes with Z3ProductSet.

## hyper_cube_set_intervals_only_experiment

### creation
- With all the different values of n_dims, there is a point where the creation time of 
CanonicalHyperCubeSet is greater than the creation time of Z3ProductSet. 
For n_dims=5 it is around 70 cubes, for n_dims=10 it is around 60 and for 
n_dims=15 it is around 50.
- It seems that the increase trend for CanonicalHyperCubeSet is super-linear
(not sure that it is exponential, but it is not a straight line).
- The increase rate for Z3ProductSet seems to be linear, as expected.
- The difference between the two implementations gets larger as n_cubes 
and n_dims increases. For n_dims=15 and n_cubes=15, 
Z3ProductSet creation time is less than 0.5 and CanonicalHyperCubeSet is around 2.
- This makes sense since most of the processing in CanonicalHyperCubeSet is done
in creation, where most of the processing in Z3ProductSet is done when checking.

### membership_test
- Membership test time seems to be relatively constant with CanonicalHyperCubeSet with 0.0 seconds,
and increasing linearly with the number of cubes with Z3ProductSet. 
The slope also increases as the number of dimensions increases.
- It appears that there are 2 lines for Z3ProductSet. 
I think that checking non-membership is harder than checking membership, and this is what leads to the two lines.

### add_hole
- Z3ProductSet times seem to be constant at 0.0 seconds, except for some out-layers.
- CanonicalHyperCubeSet time seems to be linearly increasing with the number of cubes, 
and the slope increases as the number of dimensions increases. 

### add_cube
- Results seem very similar to add_hole, just that the times appear to be smaller in general.

### contained_in 
- It appears that The CanonicalHyperCubeSet time increases super-linearly with the number of cubes. 
The more dimensions, the slope gets bigger.
- Z3ProductSet seems to be increasing linearly with the number of cubes, and has 2 slopes, Interesting why. I expect it 
to be in the example that we reduce a cube from the set, and check if it is contained in it.
- Z3ProductSet becomes more efficient at around 120 in all 3 n_dims values.

### Overall 
- With the current implementation, If we consider the setting with 1 creation (Z3ProductSet is faster) 
and 2 contained_in (CanonicalHyperCubeSet is faster). 
- The difference between the wo

### Ideas:
- [ ] repeat the first experiment with overlapping cubes. look at adi's code for inspiration. **results are way too
slow, try to make the number of dimensions smaller
- [ ] Find more interesting test cases for contained_in. Maybe look at the tests and how it is implemented in 
CanonicalHyperCubeSet can inform those.
- [ ] After dealing with integer-only cubes, start experimenting with simple string constraints.
- [ ] think about the different usage profiles that we want to compare the implementation to.
- [ ] I should consider randomly generated samples.
- [ ] Think about how to tell the story and what we discovered.
- [ ] For now, don't think about Z3ProductSetDNF, only after finishing with simple regular expressions and intervals I 
need to look into that.
- [ ] it is interesting to look at the graph where the x-axis is #cubes * #dimensions, might we get something that 
looks linear? I think that this might be the case with z3 (this is the number of constraints).
- [ ] I can actually write code that checks how much samples (under different usage profiles) are more efficient with 
Z3ProductSet and how many with CanonicalHyperCubeSet. Can I do this more methodically? 
(e.g., by fitting a curve and extrapolating).
- [x] check the granularity of the timer that I use. This might explain the discrete values that I see.
  (using time.perf_counter() instead of time.process_time())
- [x] review the findings after the granularity problem was fixed 
- [x] Create a csv format of the graphs, it might be more comfortable to use for different usages
- [x] add in the comments an example that visualizes how the inputs look like.

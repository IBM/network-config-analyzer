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
- Membership test time appears to almost constant with both, 
there are some out-layers, but it appears to be pretty constant, 
with 0.015 seconds for Z3ProductSet and 0.0 seconds CanonicalHyperCubeSet.
- The results for CanonicalHyperCubeSet are more consistent around 0.0 seconds.
- The results for Z3ProductSet are less consistent. 
It appears that there are two values that we get: 0.015 and 0.0. 
The more dimensions and cubes that we have, the value falls on 0.015, 
but this is not always the case.

### add_hole
- The values for the time seem to be discrete, I don't know why that is the case. **Interesting**. 
There are jumps with the size of ~0.015 seconds, 0.0, 0.015, 0.03, 0.045.
  - Can I explain why this happens? 
- Z3ProductSet times seem to be pretty constant at 0.0 seconds, except for some out-layers.
- CanonicalHyperCubeSet time seems to be increasing as the number of dimensions and number of cubes increases.
But it is a trend only, this does not apply to all points. 

### add_cube
- Results seem very similar to add_hole, just that the times appear to be smaller in general.

### contained_in 
- Similarly to add_cube and add_hole, the times seems to be discrete, with values in 0.0, 0.015, 0.03 and 0.045.
- In most cases, it seems that Z3ProductSet takes more time than CanonicalHyperCubeSet, but not by much, and not always.
  - It might be interesting to look at the examples where Z3ProductSet beats CanonicalHyperCube. Is there a trend there?
- It appears that both are steadily increasing as the number of cubes and dimensions raises.

### Overall 
- With the current implementation, If we consider the setting with 1 creation (Z3ProductSet is faster) 
and 2 contained_in (CanonicalHyperCubeSet is faster). 
- The difference between the wo

### Ideas:
- [ ] check the granularity of the timer that I use. This might explain the discrete values that I see.
- [ ] repeat the first experiment with overlapping cubes. look at adi's code for inspiration.
- [ ] think about the different usage profiles that we want to compare the implementation to.
- [ ] add in the comments a small example of how the input looks like, no need to document the entire thing, but only
a part of it so people can easily understand what is going on, visually.
- [ ] Create a csv format of the graphs, it might be more comfortable to use for different usages
- [ ] For now, don't think about Z3ProductSetDNF, only after finishing with simple regular expressions and intervals I 
need to look into that.
- [ ] Find more interesting test cases for contained_in. Maybe look at the tests and how it is implemented in 
CanonicalHyperCubeSet can inform those.
- [ ] I should consider randomly generated samples
- [ ] After dealing with integer-only cubes, start experimenting with simple string constraints.
- [ ] Think about how to tell the story and what we discovered.
- [ ] it is interesting to look at the graph where the x-axis is #cubes * #dimensions, might we get something that 
looks linear? I think that this might be the case with z3 (this is the number of constraints).
- [ ] I can actually write code that checks how much samples (under different usage profiles) are more efficient with 
Z3ProductSet and how many with CanonicalHyperCubeSet. Can I do this more methodically? 
(e.g., by fitting a curve and extrapolating).

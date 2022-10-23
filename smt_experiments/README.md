# Findings

## n_dims_experiment (old)

- Membership test time looks to be relatively constant with CanonicalHyperCubeSet, 
and linearly increasing with Z3ProductSet with the number of cubes.
- Z3ProductSet is slower than CanonicalHyperCube in almost all cases, except for 
when the number of dimensions is greater than 12, and the number of cubes increases exponentially.
Even in this case, creating the CanonicalHyperCube takes most of the time, and membership test is faster
with CanonicalHyperCube than with Z3ProductSet.
- Creation time seems to be linear with the number of cubes with Z3ProductSet.

## n_union_string_experiment (old)
- I think that there is some timer granularity problems as we had before.
- In all cases, membership test time is around 0.016 with Z3SimpleStringSet, and close to 0 with MinDFA.
- with only equality constraints ('constant'), the creation time seems to be lower with Z3SimpleStringSet than 
with MinDFA, even in 10 cubes. with Z3SimpleStringSet it is close to 0 and Z3SimpleStringSet it gets to 0.045 with 
25 strings.
- membership test time is lower with MinDFA (close to 0) and is greater with Z3SimpleStringSet, where it gets to around
0.015 seconds.
- results for prefix only and suffix only constraints are very similar. already at around 6 constraints the creation 
time for Z3SimpleStringSet is less than MinDFA, and with 25 constraints, it is around 0.2 seconds for MinDFA creation. 
- mixing constant constraints with prefix / suffix constraints does not seem to make the problem harder
- mixing prefix and suffix constraints does seem to make it harder for MinDFA. with 25 unions, the creation time is 
around 2 seconds. There is some double line in the prefix / suffix mixed constrains that is not so clear to me.

## multiple_string_dimensions_single_simple_cube (old)
- results are not that interesting. times are almost constant for both types of sets, and nothing 
interesting happens.

## multiple_string_dimensions_linear_number_of_non_intersecting_cubes (old)
- The results for constant, suffix and prefix constraints are similar.
- as #dims increases also #cubes increases, and also the creation time for both types of sets. 
- as with non-overlapping integer cubes, it seems to be increasing super-linearly with CanonicalHyperCubeSet, and 
linearly with Z3ProductSet.
- membership test time appears constant with CanonicalHyperCubeSet, and increasing linearly with Z3ProductSet.
- At around #dims=#cubes=10 it appears that the creation time is better with Z3ProductSet, 
- At around #dims=#cubes=16 it appears that the overall time (creation + 2 membership tests) appears to be better with 
Z3ProductSet.

## hyper_cube_set_intervals_only_experiment - non-overlapping cubes

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

## Overlapping Integer Cubes
- The results for Z3ProductSet seem to be very similar to the results with the non-overlapping cubes.
- The results for CanonicalHyperCubeSet seem to be much worse than with non-overlapping cubes. Even with 24 cubes we
get worse results than 150 cubes!

### membership_test 
- Still seems to be pretty constant with CanonicalHyperCubeSet, and linear in #cubes with Z3ProductSet
- Z3ProductSet never outperforms CanonicalHyperCubeSet.

### creation 
- CanonicalHyperCubeSet: It seems to grow super-linearly with #cubes, and the rate of increase depends significantly on 
#dims. The performance is much worse - with #cubes=24, the results for overlapping / non-overlapping are pretty drastic:


| #dims | overlapping | non-overlapping | factor  |
|-------|-------------|-----------------|---------|
| 5     | 0.19        | 0.01            | ~ 20    |
| 10    | 6.76        | 0.03            | ~ 200   | 
| 15    | 61.78       | 0.06            | ~ 1,000 |

- Z3ProductSet outperforms CanonicalHyperCubeSet when:
  - #dims=5 with #cubes=9
  - #dims=10 with #cubes=9
  - #dims=15 with #cubes=9

### contained_in
- In non-overlapping cubes, Z3ProductSet becomes more efficient when #cubes is between 100 and 120 cubes.
In overlapping cubes this happens where there are around 20 cubes. As #dims increases, then the point where Z3ProductSet
takes the advantage comes sooner.
- Also, here we can see that CanonicalHyperCubeSet is a few orders of magnitude slower with overlapping cubes.
- It is not so clear when Z3ProductSet outperforms CanonicalHyperCubesSet, since we have samples that behave 
differently, but it is somewhere around 
  - #dims=5 with #cubes=24 
  - #dims=10 with #cubes=15
  - #dims=15 with #cubes=15

### add_cube and add_hole
- As in the other operations, we can also see similar results with Z3ProductSet.
- With CanonicalHyperCubeSet we see results that are a few order of magnitude worse. 
- With overlapping cubes, we can see that Z3ProductSet out
- Z3ProductSet outperforms CanonicalHyperCubeSet when:
  - #dims=5 with #cubes=6
  - #dims=10 with #cubes=6
  - #dims=15 with #cubes=6

### Overall
- It appears that Z3ProductSet could be more efficient than CanonicalHyperCubeSet even for #cubes >= 10 and 
#dims >= 5. The higher #dims and #cubes gets, the more advantage it has.
- The exception for that is containment of sets where it becomes more efficient later, and membership check is always
more efficient with CanonicalHyperCubeSet.
- 

## string_single_dim_experiments (constant)
### contained_in
- Z3SimpleStringSet performs pretty consistently, and we can see a linear increase as the combined set size increases.
- Sometimes MinDFA performs better than Z3SimpleStringSet, and sometimes worse. When it performs better it is slightly
better, and when it performs worse, it is much worse.
- Containment time reaches to ~0.3 seconds with around ~30 strings in the set with MinDFA.
- The timing for MinDFA has a very large variation, depending on the input sets.
- It appears that Z3SimpleStringSet has an advantage when #strings > 8.

### creation
- Z3SimpleStringSet time is pretty consistent and close to 0 seconds.
- MinDFA time seems to be increasing pretty rapidly, at super-linear rate. 
- Creation time for MinDFA has a large variation depending on the exact set.
- The creation time with MinDFA is always worse than Z3SimpleStringSet, and gets to 2 seconds with #strings=20.
- It appears that Z3SimpleStringSet has an advantage from the start.

### intersection
- As before, Z3SimpleStringSet time is almost constant and is close to 0, and MinDFA has a large variation in times.
- The maximal value for MinDFA is 0.08 seconds, with #strings is ~32.
- It appears that Z3SimpleStringSet has an advantage from the start.


### membership
- MinDFA has an almost constant time close to 0.
- Z3SimpleStringSet has some variation, but not that big, and is around 0.008 at the maximal value.
- MinDFA has an advantage here.

### union
- Z3SimpleStringSet has an almost constant time close to 0.
- MinDFA time seems to be increasing linearly with #strings, the time has a large variation.
- The maximal value for MinDFA is ~0.7 seconds, with #strings=37.
- It appears that Z3SimpleStringSet has an advantage from the start.

### overall
- For all operation except for membership test, it appears that Z3SimpleStringSet performs better than MinDFA, 
especially when the number of strings increases.
- Z3SimpleStringSet seems to be pretty constant throughout.
- MinDFA times have large variations, depending on the strings it is given.

## string_single_dim_experiments (prefix)
- The results look very similar to the *constant* results, except for `contained_in`, and having a different scale.
- If I omit some operation it means that the results are the same.

### contained_in
- It seems that Z3SimpleStringSet does no longer have a clear advantage. Some examples are faster with MinDFA, and some
with Z3SimpleStringSet.
- The maximal amount of time is ~45 seconds.

### creation
- similar results as before, with the maximal time of ~9 seconds for MinDFA with 20 constraints.

### intersection
- similar to previous experiment, maximal time for MinDFA ~0.6 seconds.

### membership
- similar to previous experiment.

### union
- similar to previous experiment, maximal time for MinDFA ~3 seconds.

### overall
- note that union takes more time than intersection.

## string_single_dim_experiments (prefix + suffix)

### contained_in
- In most cases, Z3SimpleStringSet is better than MinDFA, but not for all. 
- In a small number of cases, Z3SimpleStringSet performs worse than MinDFA.
- In a medium number of cases, Z3SimpleStringSet performs similarly to MinDFA.
- The maximum amount of time for MinDFA was around 160 seconds, with around 30 constraints.
- The maximum amount of time for SimpleStringSet was around 80 seconds, with around 15 constraints.


### creation
- similar trend as in previous experiments, the maximal time being ~80 seconds with #constraints=18.


### intersection
- similar trend as before. The maximal time is ~45 seconds with #constraints ~32.

### membership
- similar trend, similar values.

### union
- similar trend, the maximal time is 140 seconds with #constraints ~40.


### overall
- with exact match constraints, it seems that Z3SimpleStringSet is a clear winner.
- with only prefix constraints, in some cases Z3SimpleStringSet is better and in some MinDFA.
- with a combination of prefix and suffix constraints, in most cases Z3SimpleStringSet is better, but in some cases

## sensitivity_to_constraint_length
- I had some thoughts that z3 might be sensitive to the length of the string constraint that it is given.
- Thus, I wanted to check that in the file `sensitivity_to_constraint_length.py`. 
- It does seem to have some effect, but not that significant.

## multiple_string_dimensions
- The results are a little unexpected. It was not a simple conclusion of the `multiple_integer_dimensions` experiment
results and the `string_single_dim_experiments` results.
- From `multiple_integer_dimensions` we would expect that Z3ProductSet gets an advantage over CanonicalHyperCubeSet
as #dims increases.
- From `string_single_dim_experiments` we would expect that Z3StringSet performs better than MinDFA when the number of 
cubes increases.
- From the previous two facts, I would expect that in multiple string dimensions, Z3ProductSet will have a clear 
advantage over CanonicalHyperCubeSet, but this does not seem to be the case. 
- It appears that the `contained_in` operation that takes the most time is checking `superset.contained_in(s)`, that is,
adding a cube to the set `s` and getting `superset`, and then checking if the new set is contained in the old set.
The solver needs to find a counter-example for that I think.
- 

### add_cube_non_overlapping
- I think that some strange results with CanonicalHyperCubeSet is due to the fact that MinDFA is using caching.
- Z3 operations are only syntactic, this makes the time pretty low.
- We see an increase in the time it takes to add a cube as #cubes increases, to about
  - 0.1 seconds in #dims=4.
  - 0.06 seconds in #dims=8.
  - 0.06 seconds in #dims=12.

### add_cube_overlapping
- Similarly to the non-overlapping case, the longest time is for #dims=4 which I think might be due to caching with 
MinDFA.
- The time increases as #cubes increases, and gets to:
  - 10 seconds with #dims=4
  - 2 seconds with #dims=8
  - 5 seconds with #dims=12

### add_hole_non_overlapping
- Similar trend as add_cube, but the numbers are lower.
  - 0.01 for #dims=4
  - 0.01 for #dims=8
  - 0.0125 for #dims=12

### add_hole_overlapping
- It appears that most of the results are quite similar and fast, but some take significantly longer, like
#cubes=21, and #dims=4, or #dims=12 which take significantly more than the rest of the points. I suspect that it might 
be due to caching.
- highlights:
  - 8 seconds with #dims=4, #cubes=21
  - 0.8 sec with #dims=8, #cubes=24
  - 5 seconds with #dims=12, #cubes=21

### contained_in_non_overlapping
- In this case, it is pretty obvious that CanonicalHyperCubeSet outperforms Z3ProductSet, by a few orders of magnitude.
- with #dims=4, #cubes=24 it gets to ~25 seconds 
- with #dims=8, #cubes=24 it gets to ~40 seconds
- with #dims=12, #cubes=24 it gets to ~200 seconds
- In some cases Z3ProductSet takes more time, and less in others. It is interesting to characterize this.
- In all of the above, CanonicalHyperCubeSet time is close to 0.

### contained_in_overlapping
- In this case, there is more competition between Z3ProductSet and CanonicalHyperCubeSet.
- It appears that there is 1 example that takes Z3 more time, and the other examples are OK.
- with #dims=4, Z3ProductSet and CanonicalHyperCubeSet perform comparably. for some instances Z3ProductSet is slower,
and for others, CanonicalHyperCubeSet is slower. The longest time for both is with Z3, ~20 seconds.
- with #dims=8, Z3ProductSet (on the tough example) is slower than CanonicalHyperCubeSet. The worst time gets to around
30 seconds, with Z3ProductSet.
- with #dims=12, it is again not so clear which is preferable, Z3ProductSet or CanonicalHyperCubeSet. The worst time is 
~30 seconds with both CanonicalHyperCubeSet and Z3ProductSet.

### creation_non_overlapping
- we can see a steady growth in time as #cubes increases.
- the times for #dims=4 is the highest, I suspect it is an effect of caching. 
- The top time is 0.2 seconds with #dims=4, and ~0.15 seconds with #dims=8,12.

### creation_overlapping
- We can see that the creation times with CanonicalHyperCubeSet are worse with overlapping cubes.
- We can see a similar trend to the non-overlapping case, but with higher numbers:
  - #dims=4, ~15 seconds
  - #dims=8, ~5 seconds (I think that we get a faster time than with #dims=4 is due to MinDFA caching)
  - #dims=12, ~25 seconds

## Analyzing traces
### How to run analysis:
- The trace files are currently in .gitignore since they are quite large. To create them:
  - run `canonical_hyper_cube_set_tracker/trace_benchmarks.py` to collect the traces from the benchmarks.
- The following files are in the repo since they are smaller, but creating them
requires that we have the trace files mentioned above: 
  - from `analyze_traces.py` run the function `analyze_min_dfa_list()`.
    - This will create the file `canonical_hyper_cube_set_tracker/analysis_results/min_dfa.json` that contains
    the MinDFAs that appear in the run of the benchmarks. This will also print percentage of 
    exact match constraints.
  - from `analyze_traces.py` run the function `analyze_usage_profiles()`.
  - This will create the file `canonical_hyper_cube_set_tracker/analysis_results/most_common_operation_sequences.txt`
  that contains a list of the most common sequence of operations on an instance of CanonicalHyperCubeSet
  that occur when running the benchmarks.

### Observations
- I should be careful to draw conclusions from the traces, since a lot of them are tests, and the benchmarks
are not that diverse.
- MinDFA constraints: Out of 751 MinDFA constraints given to CanonicalHyperCubeSet operations, 361 (49%) are
exact match constraints, meaning that there might be something to improve if we consider this special case.
- The usage profiles appear in the file `smt_experiments/canonical_hyper_cube_set_tracker/analysis_results/most_common_operation_sequences.txt`
but I'm not so sure how to interpret that, maybe we should take some of the most common once and use that for evaluation?

## dnf_scalability experiments
- The results for string constraints and integer constraints are similar, with string constraints
having some extra overhead time, but not substantial compared to the total time.
- Z3ProductSetDNF is very slow. It takes ~1700 seconds for a `contained_in` operation 
that takes 0.002 for CanonicalHyperCubeSet, with #dims=3, #cubes=4.

## realistic_samples experiment
### contained_in
- There are a lot of points in the graph. 
- It appears that in most places, Z3ProductSet and CanonicalHyperCubeSet perform quite similarly, but,
in many instances Z3ProductSet takes significantly longer to run. 
- The longest time for Z3ProductSet is ~45 seconds.
- The longest time for CanonicalHyperCubeSet is ~5 seconds.

### creation_and_emptiness
- In most cases, Z3 and CanonicalHyperCubeSet take similar time to run.
- It appears that in some cases, CanonicalHyperCubeSet takes significantly more time than Z3ProductSet.
- There is one sample, with id ~35 where Z3ProductSet takes significantly more time than CanonicalHyperCubeSet.
- The longest time that CanonicalHyperCubeSet takes is ~7 seconds.
- The longest time that Z3ProductSet takes is ~11 seconds.

### equivalence
- most points are pretty close to 0 seconds, but, Z3ProductSet clearly takes more time than CanonicalHyperCubeSet,
in many points.
- The longest time for Z3ProductSet is around 25 seconds.
- The longest time for CanonicalHyperCubeSet is around 0 seconds. 


# Ideas:
- [ ] (priority) presentation (30 min).
- [ ] (priority) realistic hyper-cube experiment
- [ ] (priority) analyze benchmarking results.
- [ ] (priority) discuss adi about closing things up.
- [x] (priority) Analyze the results that we got with multiple string dimensions.
  - I think that we get some weird results due to MinDFA caching.
- [x] (priority) Figure out what are the instances of Z3 that take more time for it to solve.
- [x] (priority) add regex to `string_single_dim_experiments`.
- [x] (priority) add regex to `multiple_string_dimensions` and `Z3ProductSetDNF`.
- [ ] SMT optimizations. -- If I have the time, experiment with this.
  - [ ] Benchmark the z3 sets, to help optimizations.
  - [ ] experiment with using `simple_solver` instead of the default one.
  - [ ] instead of creating a new solver every time, try to share the solver between instances.
  - [ ] trying out different solvers (cvc5).
  - [ ] Use the simplify method similar to the one in
[Z3 programming](https://theory.stanford.edu/~nikolaj/programmingz3.html#sec-subterm-simplification).
  - [ ] using z3 bit-vectors to represent things instead of integer sets?
- [ ] Re-run the experiments that involve string constraints, with caching disabled.
- [ ] String experiment with simple constraints.
  - [x] Analyze the results that we have from the previous experiments.
  - [x] Implement experiment.
  - [x] Analyze results of experiment. (still need to analyze prefix + suffix)
  - [x] add csv tables?
  - [x] Continue with multiple only string dimensions, and overlaps.
  - [ ] Extend this to mixed dimensions.
  - [x] Experiment with regex.
- [ ] It seems that in some graphs there are different trends. Figure out what are does trends, and what causes them.
- [ ] Usage profiles that we want to compare the implementation to.
  - [x] Collect traces from benchmarks and the tests, so that I have a database of real usage profiles.
  - [ ] Analyze those, can I characterize them in some way?
- [ ] Implement a prototype of MBDDs.
- [ ] Hybrid string set. Instead of MinDFA, some sort of hybrid string set that only uses MinDFA when it is required.
- [ ] Figure out how the number of dimensions affects things (mathematical description).
- [ ] Figure out where is the limit where z3 based implementation outperforms the tree-based implementation.
- [ ] Find more interesting test cases for contained_in. Maybe look at the tests and how it is implemented in 
CanonicalHyperCubeSet can inform those.
- [ ] Experiment with randomly generated samples.
- [ ] It is interesting to look at the graph where the x-axis is #cubes * #dimensions, might we get something that 
looks linear? I think that this might be the case with z3 (this is the number of constraints).
- [ ] I can actually write code that checks how much samples (under different usage profiles) are more efficient with 
Z3ProductSet and how many with CanonicalHyperCubeSet. Can I do this more methodically? 
(e.g., by fitting a curve and extrapolating).
- [x] maybe create a plot of overlapping and non-overlapping cubes?
- [ ] look for projects using z3 and try to figure out how they use it, and if they do anything differently.
- [ ] perform scalability analysis - how different parameters affect the running time (mathematical description)
and use that to determine under what circumstances it might be better to use one implementation over the other.
- [ ] Another thing that I might want to check is how the length of the string constraints affects performance. 
- [x] make the `.csv` table have two columns - one Z3ProductSet and one for CanonicalHyperCubeSet.
- [x] Analyze results with overlapping cubes.
- [x] repeat the first experiment with overlapping cubes. look at adi's code for inspiration.
- [x] check the granularity of the timer that I use. This might explain the discrete values that I see.
  (using time.perf_counter() instead of time.process_time())
- [x] review the findings after the granularity problem was fixed 
- [x] Create a csv format of the graphs, it might be more comfortable to use for different usages
- [x] add in the comments an example that visualizes how the inputs look like.


# Notes about the experiments:

## Parameters to study:
1. (engine) How is the set represented? could be one of CanonicalHyperCubeSet, Z3ProductSet, Z3ProductSetDNF.
2. (#cubes) How many cubes do we have in the creation of the set?
3. (operation) Which operations do we preform on the sets? membership, containment, equality, creation.
4. (???) Relations between the cubes - are the cubes overlapping?
5. (#dims) The number of dimensions.

## Things to note when preparing an experiment:
- Simple readable graph.
- It should be clear what are the inputs and output of the experiment.
- Describe the outcome / results.
- Separate running the experiment and plotting the results.
- Engine is always the parameter that appears in the legend of the plot, for now.
- Don't write the program from scratch. Reuse code from previous experiments.
- Export raw results to `.csv` so we can analyze them with EXCEL.
- Separate experiments into different directories, for convenience.
- Add a description for every experiment discussing:
  - The question that the experiment is designed to answer.
  - A sketch of the experiment.
  - What are my expectations? What do I think that is going to happen?
- Add asserts in the code to make sure that we get the expected results and, 
This will give more validity to our results.
- 




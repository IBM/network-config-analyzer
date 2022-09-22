# Experiment Results

## n_dimensions_experiment:

### description:
This experiment is measuring the *creation time* and 
*membership time* for hyper-cube-sets, using z3 and our 
implementation.
- time is in seconds.
- the titles `constant`, `linear` and `exponential`
refers to the number how many cubes there are in relation to the number 
of dimensions. 
  - `constant` there is always 1 cube,
  - `linear` same number of cubes as the number of dimensions
  - `exponential` 2^(#dimensions) cubes.
- We distinguish between the time it takes to test if an element is in the set (contained)
and if element is not in the set (not_contained)

### Notes on results:
- membership check time is bigger in Z3 than in our implementation in the 
`constant` and `linear` number of cubes. in the `exponential` number of cubes we see
an exponential time increase with Z3. It takes 0.2 seconds with 15 dimensions (the most we tried)
- the creation time of the two sets is almost the same in `constant`,
but in `linear` it seems that the creation time in Z3 becomes better than 
ours at around 10 dimensions. in 15 dimensions, z3 creation time is 0.03, and ours is ~0.06.
- in `exponential` it seems that the creation time is exponential with both sets, but the hyper cube 
seems to be growing much faster, taking 160 second in 15 dimensions compared to ~50 seconds with z3.

## n_unions_string_experiment
In this experiment I compare between the creation time and membership check time of
string sets represented by Z3 and MinDFA.

I generate the sets by taking a union of any combination of the following base sets:
1. constant - a singleton containing only a single string.
2. prefix - any string that starts with some string
3. suffix - any string that ends with some string

I distinguish between membership test when the result is True and when it is False.

### Notes on results:
- membership test time seems to be pretty constant, around 0.01 seconds for z3 and 
order of magnitude smaller for our implementation (in the graph appears to be 0)
- the creation time for z3 seems to remain pretty constant (probably linear), but with our implementation it 
seems to grow exponentially, especially when we use prefix or suffix.
and gets to 15 seconds when 3 modes are combined (prefix, suffix and constant) with 14 unions 
(which is actually 14 * 3 unions since we have a different set for each mode)


## multiple_string_dimensions Notes:
- when there is only a single cube, the z3 implementation and our implementation have constant runtime,
and the z3 runtime is much worse. but this does not depend much on the number of dimensions.
- but, when we have a linear number of cubes (#cubes = #dimensions) the construction time of our set is greater, 
but membership checking appears to be faster in our implementation, but overall, z3 becomes better than our 
- implementation at around 13 dimensions (in the simple cubes experiment).
- 


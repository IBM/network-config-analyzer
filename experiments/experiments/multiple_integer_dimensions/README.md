# Multiple integer dimensions
This experiment is designed to answer the question, 
how n_cubes affects runtime of different operations, when n_dims is fixed and the dimensions are all intervals?

We fix the value of n_dims to one of {5, 10, 15}, and increase n_cubes.
One time we use non-overlapping cubes, and one time we use overlapping cubes.
Then we plot 3 graphs, one for each value of n_dims, with the runtime over the n_cubes parameter.

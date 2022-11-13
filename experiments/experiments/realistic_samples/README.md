# Realistic samples experiment
## Description
In this experiment, we compare the 3 hyper-cube-set implementations (classes) - `CanonicalHyperCubeSet`, `HyperCubeSetDD` and 
`Z3ProductSet` on examples that have the same fields as in NCA.

We start from a set of configurations found in the file `connection_attributes_list.py`.
In this file you can find two lists - `simple` and `complex`.
The `simple` list contains realistic examples that are common in the use-cases of NCA.
The `complex` list contains more complex examples that are possible to generate in Kubernetes,
but are not likely to appear in a real cluster.
We refer to `simple` and `complex` as *modes*.

In `create_connection_set_combinations.py` we mix the examples into pairs of `allow_list` and `deny_list`.
Each `allow_list`, `deny_list` pair is used to construct a hyper-cube-set, 
by allowing connections from `allow_list` and denying connections from `deny_list`.

For each class we perform 3 operations:

1. *creation + emptiness*: for each `allow_list`, `deny_list`, we create the hyper-cube-set and check if it is empty.
2. *creation + equivalence*: 
for each two pairs of `allow_list`, `deny_list` (without order, without repetition)
we create the two hyper-cube-sets and check if they are equivalent.
3. *creation + contained_in*: 
for each two pairs of `allow_list`, `deny_list` (with repetition, with order) we create the two hyper-cube-sets 
and check if the first is contained in the second.


Note that before each operation we clear the caches, both of that of `MinDFA` and `DecisionDiagram`, 
since each operation simulates a new run of NCA.
If we would not clear the cache for `MinDFA` then `CanonicalHyperCubeSet` and `HyperCubeSetDD` would have an unfair
advantage over `Z3ProductSet`, and if we would not clear the cache for `DecisionDiagram`, `HyperCubeSetDD` would have
an unfair advantage over the other two classes, by reusing computations from previous runs.


## How to run
First, you need to run the experiment and record the results for each class and mode (in this example it is `CanonicalHyperCubeSet` and 
`simple`):
```commandline
python experiments/experiments/realistic_samples/run_experiment.py --cls="CanonicalHyperCubeSet" --mode="simple"
```
If you do not specify `--cls` or `--mode` then it will run over all options. Run 
`python experiments/experiments/realistic_samples/run_experiment.py -h` for more information.

Then, to create the tables and draw the graphs, you need to run (in this example, it will compare 
`CanonicalHyperCubeSet` and `Z3ProductSet` on the `simple` mode):
```commandline
python experiments/experiments/realistic_samples/analyze_results.py --cls1="CanonicalHyperCubeSet" 
--cls2="Z3ProductSet" --mode="simple"
```
If you do not specify `--cls1`, `--cls2` or `--mode` then it will run over all options.
Run `python experiments/experiments/realistic_samples/analyze_results.py -h` for more information.


## How results are organized
Inside the directory `experiment_results` you can find the following files:
- For each class and mode you will find a file `{class}_{mode}.json` containing the raw results of the experiment.
- For each pair of classes, `cls1`, `cls2` and mode `mode`, you will find a directory `{cls1}_{cls2}_{mode}` containing
a comparison between the two classes on the examples from `mode`.
  - `{operation}.csv` - a table comparing the results of an operation between the two classes.
  - `{operation}.png` - a graph visualizing the results of an operation between the two classes.
  - `summary_table.csv` with summary statistics of the results.

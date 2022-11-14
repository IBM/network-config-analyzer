# Experiments
This directory contains the code for running the experiments and analyzing the results.

## Directory Structure
- `experiments` - contains code for new experiments. 
Each subdirectory represents a single experiment.
  - `experiment_utils.py` contains code that is shared by the different experiments.
  - `realistic_samples` is described in more details in the `README.md` file in that directory.
  - Every subdirectory except for `realistic_samples` contains:
    - `run_experiment.py` a script that 
    runs the experiment and generates outputs based on the results in the same directory. 
    To run the experiments, simply execute the `run_experiment.py` script.
    The outputs are in the following formats - 
    `.json` files contain the raw measurements.
    `.csv` files contain the measurement in a more readable format that can be opened and manipulated with 
      a spreadsheet editor.
    `.png` files contain graphs that visualize the results.
    - `README.md` that describes the experiment.
- `expetiments_old` - contains code and results for the initial experiments. 
Each experiment in this directory measures 4 operations time - 
set creation, positive membership, negative membership and the sum of the previous 3. 
Those experiments compare Z3 and our implementation (`CanonicalHyperCubeSet`). To run an experiment simply run the script with the experiment name, e.g., `multiple_string_dimensions.py`.
  - `experiment_results` contains `.json` files with the raw measurements of the different experiments.
  - `plots` contains graphs that visualize the experiments results.
  - `experiment_util.py` contains utility code for the experiments.
  - `multiple_string_dimensions.py` is an experiment that compares the effect of the number of dimensions
  on the operation times, when all the dimensions are of string type. It has two modes:
    - linear increase in number of cubes - the number of cubes in a set is equal to the number of dimensions.
    - single cube - always there is a single cube in the set.
  - `n_dims_experiment.py` an experiment that compares the effect of increasing the number of dimensions
  on the operations time, when all the dimensions are of int type. It has three modes:
    - constant - always a single cube, no matter how many dimensions there are.
    - linear - the number of cubes is equal to the number of dimensions.
    - exponential - the number of cubes is `2 ** n_dims`.
  - `n_intervals_experiment.py` an experiment that compares the effect of increasing the number of intervals in a 
  single interval set on the time of the operations. 
  - `n_unions_string_experiment.py` - compares the effect of the number and type of string constraints on 
  the operations time of `MinDFA` and `Z3SimpleStringSet`. We use 3 different types of string constraints - `suffix`, 
  `prefix` and `constant` and their combinations.
  - `run_experiment.py` contains the core code that runs the experiments.
  - `plot_experiment_results.py` code for plotting the results of the experiments.
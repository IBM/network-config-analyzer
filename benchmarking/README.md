# Benchmarking

## How to run
1. place the benchmarks in the `benchmarks` directory, each in its own directory
2. make sure that an appropriate `*-scheme.yaml` file exists in the `benchmarks` directory
   - for creating a scheme file from a template run the script `create_scheme_files.py` and then modify it if needed
3. run `python run_benchmarks.py --experiment_name=<experiment_name>`, this will run all the benchmarks and save the 
results to `benchmark_results/<experiment_name>` and create a report


## Visualizing profile results
After running the benchmarks, and getting the profiling result we can 
visualize the results.
I use the profiling tool [gprof2dot](https://github.com/jrfonseca/gprof2dot).

In order to use it, we need to install the tool with the command:
```commandline
pip install gprof2dot
```
And install [graphviz](https://graphviz.org/download/) to render it to an image.
Make sure to add `graphviz` to `PATH`.

To visualize a profiling result saved to file `<profiler_output_file>` we can run:
```commandline
gprof2dot --colour-nodes-by-selftime -f pstats <profiler_output_file> | dot -Tpng -o output.png
```
Note that functions are colored by the percentage of time that the program spends 
in them (tottime).

To visualize all the profile results you can run [TODO]

### gprof2dot options
- 

## TODO
- [ ] create a script that generates the images


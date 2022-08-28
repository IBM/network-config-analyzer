# Benchmarking

## How to run
1. place the benchmarks in the `benchmarks` directory, each in its own directory
2. make sure that an appropriate `*-scheme.yaml` file exists in the `benchmarks` directory
   - for creating a scheme file from a template run the script `create_scheme_files.py` and then modify it if needed
3. run `python run_benchmarks.py --experiment_name=<experiment_name>`, this will run all the benchmarks and save the 
results to `benchmark_results/<experiment_name>` and create a report

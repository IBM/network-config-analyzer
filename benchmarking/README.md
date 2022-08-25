# Benchmarking

## How to run
1. place the benchmarks in the `benchmarks` directory, each in its own directory
2. make sure that an appropriate `*-scheme.yaml` file exists in the `benchmarks` directory
   - for creating a scheme file from a template run the script `create_scheme_files.py` and then modify it if needed
3. run `python run_benchmarks.py --experiment_name=<experiment_name>`, this will run all the benchmarks and save the 
results to `benchmark_results/<experiment_name>` and create a report

## TODOs

### Next Iteration
This is a list of improvements to the benchmarks and the reporting to do in the next iteration:

- [ ] add the tests to the benchmarks 
  - Note -- there are tests that run several queries. 
  - [ ] group the tests by the type of query that they run to be consistent with the current format
- [ ] add support for `FromJakeKitchener` benchmark
- [ ] two options to audit the parameters:
  - [ ] add specialized functions to get the required parameters for auditing without running the benchmarks. 
  This will not require to change existing functions and will not add overhead.
  - [ ] use logging - might require changing existing function code, but is easier to implement and easier to track 
  parameters in that way
- [x] remove the list in the `timing_report.csv`
- [x] limit the number of digits after the `.`
- [ ] add the type of layer (or the list of layer types)
- [ ] add support for other queries (comparing two policies)
  - [ ] permit / forbid queries
  - [ ] semantic diff. 
  - [ ] automatically generate the other policy
- [ ] save the profiling results. place them in a different directory
- [ ] add the `percall` statistics to the report (time per function call)
- [ ] add percentage of time in each function to the report
- [ ] show the same statistics for total time similarly to cumulative time.
- [ ] show more than 20 top records
- [ ] add readme on how to run the benchmarks on the server -- don't post internal things on open source repo
- [ ] checkout visualizations tools to the profiling results
- [ ] think about how to extend the benchmark

### Other Improvements (not in the next iteration)
- [ ] checkout tools like `line_profiler`, `memory_profiler` and 
`continuous monitoring`
- [ ] maybe open source benchmarks?
- [ ] talk with ziv about logging options
- [ ] -- compare running connectivity with .dot and .txt
- [ ] add documentation of how to run stuff
- [ ] list on box of possible things to look at

# TODOs

## Next Iteration
This is a list of improvements to the benchmarks and the reporting to do in the next iteration:

- [x] add the tests to the benchmarks => there are tests that run several queries. 
  - [x] group the tests by the type of query that they run to be consistent with the current format -- 
  I can do that by splitting the scheme files into multiple files with a single query.
  - [x] I'm adding support for the scheme files, but I'm waiting for adi to let me know if support for the other 
  things is important (CLI, github, live cluster) -- only support for the scheme files is required.
  - [x] add a query type as a field to the benchmark report
- [x] add support for `FromJakeKitchener` benchmark -- reorganized the directory and removed unnecessary files
- [x] add support for other queries (comparing two policies)
  - For each query, compare it with allow-all-default and a single policy from the benchmark
    - [x] permit  
    - [x] forbid queries
    - [x] semantic diff
    - to forbid we can take one of the ports that we want to block
    - try to thing about real use cases are allowed / denied.
    - semantic-diff: change small things like port num.
- [x] checkout visualizations tools to the profiling results
- [x] compare running connectivity with .dot and .txt -- I'm
not sure about this option, should we add some extra flags? for running with fw-rules? Ask Adi. 
For now, I'm just adding the two different queries, one with `dot` output and one with `txt`
- [x] two options to audit the parameters: => ask Ziv about that.
  - add specialized functions to get the required parameters for auditing without running the benchmarks. 
  This will not require to change existing functions and will not add overhead.
  - use logging - might require changing existing function code, but is easier to implement and easier to track 
  parameters in that way -- I decided to go in that way. I might want to use a different method and process 
  "on the fly" the incoming records, this is important if I want to make a histogram of the 
  number of intervals for example.
- [x] New parameters to audit => do that after deciding how to collect the parameters.
  - [x] add the type of layer (or the list of layer types)
- [x] do some work on documentation and usability
- [x] remove the list in the `timing_report.csv`
- [x] limit the number of digits after the `.`
- [x] save each type of result (profiling, auditing, timing) in a different directory
- [x] add the `percall` statistics to the report (time per function call)
- [x] add percentage of time in each function to the report
- [x] show the same statistics for total time similarly to cumulative time.
- [x] show more than 20 top records


## Other
- [ ] think of other ways to extend the benchmarks
- [ ] discuss ziv how to integrate this in the code, and if we should.
- [ ] checkout tools like `line_profiler`, `memory_profiler` and 
`continuous monitoring`
- [ ] adding open source benchmarks?
- [ ] list on box of possible things to look at
- [ ] get feedback about the policies that I use in the two policies queries
- [ ] add readme on how to run the benchmarks on remote server => make sure to not push that into the GitHub
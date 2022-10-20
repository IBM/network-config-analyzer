# Realistic Samples Comparison
## Plan
1. Create a list of policies with the standard fields (src_ports, dst_ports, methods, paths, ...) 
of around 15 relatively complex sets.
2. Create a mixture of subset of those - some with allow, some with deny, and some that are not used. - around 100?
3. For each mixture of allowed, deny, not used, run some "sanity checks":
    - is there any rule that is contained in another?
    - is there any rule that is redundant? (that is, adding it last does not affect the resulting set)
    - aggregate all rules and check emptiness.
4. Collect statistics on the above checks, and compare z3 and canonical representation.

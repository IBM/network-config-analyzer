## Possible solutions
- [ ] First try to do a solution involving only prefix and suffixes
- [x] using a different solver -- quick check: does not seem to help.
- [ ] maybe writing the terms differently. 
  - [ ] A problem might be when we have several `InRe` with the same variable. 
  We might need to reduce the formula down to use a single `InRe` for each type, 
  maybe with disjunction.
- [ ] Using z3 tactics:
  - [ ] find out all tactics using z3.describe_tactics().
  - [ ] try `elim-and` that eliminates Ands
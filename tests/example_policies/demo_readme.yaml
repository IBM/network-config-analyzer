##################################################################################################
#### priority 1:
##################################################################################################
#### those examples describe real policies with problems that can be revealed by the tool in a regression process (not policies that were written only to demonstrate a problem)

#### testcase4 with equivalence 
  #### demonstrates the common mistake of adding a redundant '-' while trying to combine namespace selector with pod selector (which is not possible)
#### testcase6 with interfere
  #### demonstrates non-desired communication as result of un-awarness of the exact pods space (specifically, that there is a pod that shares two specific labels)
#### testcase8 with redundancy
  #### demonstrates the common mistake of redundant '-' before ports


##################################################################################################
#### priority 2: 
##################################################################################################
#### testcase2 with equivalence
  #### demonstrates the delicate difference in semanic between the "in" operator and the "not in" operator that can cause mistakes
#### testcase1_tag with equivalence and redundancy
  #### demonstrates the ability of the tool to compare policies written with different semantic (e.g. ingress vs. egress) and to find cool redundancies
#### testcase1 with redundancy and equivalence
  #### demonstrate the mistake I did due to the confusing semantic of using []

##################################################################################################
#### Leftouts
##################################################################################################
#### testcase3
  #### demonstrates the problem of redundant '-' before ports by comparing to the correct implementation
#### testcase5 
  #### not a very good example due to the randomality of the witness chosen by equiv query when not equivalent; interfere for this example is too broad
#### testcase7
  #### weakness here is that interfere for this example is too broad
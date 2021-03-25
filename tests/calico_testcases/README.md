testcase1
=========
Idea: Comparison between syntactically identical network policy and global network policy which are equivalent. Uses selector, protocol and namespaceSelector
global networkpolicy and networkpolicy
equivalence
Single Rule. Ingress and Egress
Rule uses: Action - Allow, protocol, source, destination 
EntityRule uses: Selector, protocol and namespaceSelector 
Selector uses: k==v, has(k)

Content: Two network policies and one global network policy.  
The 2 local polices isolate in kube-system namespace pods with tier frontend. 
The global policy isolate just pods with tier frontend.
However, since there are such pods only in kube-system the results should be identical.
For the global policy and networkpolicy2,
Ingress is enables only from namespace default on TCP and egress only from pods with "app": "keepalived-watcher". 
Since there are pods with "app": "keepalived-watcher" only in namespace kube-system, both policies should be identical.

networkpolicy1 isolates as above, with the difference that it enables egress only from pods that has label app.
Since in Kubesystem there are pods with app !=  "keepalived-watcher" this policy should be distinct.

results as expected

testcase2
=========
Idea: Comparison between syntactically identical network policy and global network policy which are not equivalent due to the captured set
containment
global networkpolicy and networkpolicy
Single Rule. Ingress and Egress
Rule uses: Action - Allow, protocol, source, destination 
EntityRule uses: Selector, protocol and namespaceSelector 
Selector uses: k==v, has(k) 
Both policies isolate pods with tier defined. In addition, the (local) networkPolicy isolates pods in kube-system namespace. 
Since tier is also defined in other namespaces (e.g. default), the global networkPolicy isolates more pods. 
ingress is enabled only from namespace default on TCP. 
Egress is enabled from all pods with label app = 'keepalived-watcher'; since there are such pods only in namespace kube-system, the ingress and egress defines the same set of endpoints. 
To summarize, egress and ingress are the same but more pods isolated in global. Thus, global should be contained in local. 

results as expected

testcase2tag
============
Idea: Comparison between syntactically identical network policy and global network policy which are not equivalent due to egress and ingress set
containment
global networkpolicy and networkpolicy
Single Rule. Ingress and Egress
Rule uses: Action - Allow, protocol, source, destination 
EntityRule uses: Selector, protocol and namespaceSelector 
Selector uses: has
Both isolate the same set of pods - as in testcase1, but enable egress and ingress as in testcase2. Thus, here the global should contain the local
 
results as expected

testcase3
=========
Idea: Play with two rules: allow and deny s.t. the deny is a subset of the allow.
Have three policies: 
1. Only allow
2. Alow and then deny
3. Deny and then allow
Policies 1 and 2 should be equiv, and contain policy3
equivalence, containment
network policies.
Single or Two rules.  Ingress
Rule uses: Action - Allow, deny, protocol, source 
EntityRule uses:  Selector
Selector uses k in {v1, v2}
pending issue for Ziv

results as expected

testcase4
=========
Idea: Comparison between global policies one with Selector and the other with NotSelector s.t. one semantically (not syntactically) negates the other also with namespaceSelector
Thus, they are identical w.r.t. Calico but not w.r.t. the outside world. Should we provide some matching warning?
equivalence
global network polices.
Single rule. Ingress, Egress
Rule uses: Action - allow, protocol, source, destination
EntityRule uses: Combination of selector/notSelector and NameSpaceSelector

results are as expected

testcase5
=========
Idea: Comparsion between two policies with an identical 'Allow' rule and 'Deny' rule that differs only in the order of the rules, 
such that the intersection between them is not empty. 
Thus, one policy should be contained in the other.
equivalence, containment
network policies. 
Two rules. Ingress.
Rules uses: Action - Allow/Deny, Source
EntityRule uses: selector
Selector uses: has(k), !has(k)
Content: Namespace "kube-system", allow: has(tier), deny: !has(app). 
Since has(tier) && has(app) is not empty, and since has(tier) && !has(app) is not empty, in both combinations of order the allowed sets are not empty and they differ from each other

results are as expected

testcase6
=========    
Idea: Two rule entities s.t. one contains the other but in a non-trivial way. 
Construct from these four policies which are the cartesian product of the order and allow/deny (one for each).
network policies.  
Two rules, egress
Rules uses: Action- Allow/Deny, Destination. 
equivalence, emptiness, redundancy, containment 
Note: none of the policies are equiv; all contained in superAllow, superDeny defines an empty policy

results are as expected

testcase7
=========
Idea: Play with a 'selector' and a 'notSelector' 'Allow' s.t. neither is contained in the other, and thus their 'or' differs their 'and'
Two policies: one with both selector and not selector in the same rule and one with two different rules.
Since the first is 'and' and the second is 'or' the first should be contained in the second.
In addition, another policy with a rule that selects no pods. That one should be empty.
global network policies
Two rules, egress
equivalence, emptiness

results are as expected

testcase8
=========
Idea: ingress policy in which 'destination' is specified, egress in which 'source' is specified. 

results are as expected

testcase9
=========
Idea: compare a policy with selector all() and protocol TCP to a policy only with protocol TCP. 
Due to communication outside the cluster they are not equiv.   

results are as expected.   

testcase10
==========
Idea: global and local policy with combination of ingress/egress types and rules.
Cases in which either does not have rules or defines no connections
Cases in which types defined but rules do not have a type the rules should receive error message.
Check various emptiness, vacuousness, redundancies, containment and equivalence.
Note that a policy with only "Allow" ingress/egress is not vacuous  

results are as expected.  


testcase11
==========
Idea: similar to testcase5, only different policies (instead of rules) with order. And add a default allow all in one set.

results are as expected 

testcase12 - interferes
=======================
PairwiseInterference. Checks include policies with several rules, cfg of several policies, local and global policies.
 Check the following:
1. Same set of captured pods
2. Policies from testcase5 and 11 which plays with the order between 
3. policies defined over a different set of captured pods 

results as expected 

Once profiles are supported - add to testsuite

protocol
=========
* same protocol - equiv (testcase1)
* not same protocol - not equiv (testcase1)

testcase13-protocol
===================
1. egress, ingress defined for different protocol - resulting policy is vacuous. 
   Both local and global 
2. protocol and notProtocol and combination of these works as expected 
3. Deny behaves as expected

results are not as expected

testcase14-icmp
================
similar to testcase13, only with icmp-type and code and type

results not as expected

testcase15-ports
================
tests include:
* match between egress and ingress
* mismatch between egress and ingress
messy - including ports, not ports, deny, allow

* Equivalence and non-equivalent examples. Make them messy, including ranges and deny. 
Have 2 files: 
 One with two policies which are equivalent in a non-trivial way. Also check redundancy
 One with two policies which are non-equivalent in a non-trivial way. Also check redundancy

Tests with source ports are not working properly - seems we will not be supporting these. 

results not as expected

testcase16-nets
================
Games with nets, not nets, allow, deny and different writing styles.

Not working as expected


Perhaps add test of equiv by ingress in one end and egress in the other

testcase17-sanity
==================
vacuous config
empty policy - done
vacuous non-empty policy - done
empty egress and ingress rule - done
empty (and redundant) ingress and egress rules in non-empty and non-vacuous policy - done 
redundant ingress and egress rules in non-empty and non-vacuous policy - done
redundant NetworkPolicy not due to simple containment or emptiness/vacuity - done

ToDo:
check Allow containment in lower order policy; should not be given as an explanation 


testcase19-profiles
===================
testcase19-global-ingress-all-egress-offering.yaml opens ingress to all and egress to those with label offering
testcase19-global-ingress-all-egress-offering-plus-label-equiv.yaml in addition opens egress to  10.73.127.7-k8s-helm--tiller--54fd7577cb--lcttr-eth0
    This is done with label  "my-unique-label": "the-only-acc-research"
testcase19-global-ingress-all-egress-offering-plus-profile-equiv.yaml equiv to the previous one. Only it opens the additional egress by applying label offering to 
    profile kns.acc-research
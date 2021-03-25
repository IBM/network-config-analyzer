There are three folders here, following the stages in developing and maintaining network policies:
- __sanity__ - tests that should be executed after writing or modifying a policy
- __interferes__ - test that should be executed when access to a specific set of pods should be defined exclusively in a specific policy
- __regression__ - tests that should be executed when modifying a policy

##sanity:
The sanity folder contains policies and schemes for demonstrating the capabilities of our sanity checks
1. The "good practice" warnings:
    * A podSelector selects no pods. Better use "PodSelector: Null"
    * A podSelector selects all pods. Better use ""
    * Both cases above are likely a result of a mistake.
2. Emptiness. A policy that does not enable any connections. Could be a result of a mistake.
3. Redundancy. A policy or a rule in a policy is redundant w.r.t. the other policies or the other rules in the policy if removing it will have no effect.
Unless a policy is intended only to isolate specific pods, it is not likely to empty. 
Clearly, a rule in a policy is not likely to be redundant w.r.t. other rules in the policy.
Thus, a good practice should include emptiness and redundancy tests for all policies written or modified.

sanity folder contains the following files:
* _sanity-label-mistake-networkpolicy.yaml_ demonstrates the ability of the emptiness test and the first good practice rule to detect mistakes.
The mistake concerns using the app label instead of the k8s-app label (they both exist) as a result of which the podSelector is empty.

* _sanity-misconsuption-podSelector-namespaceSelector.yaml_ is yet another example of the ability of the redundancy tests and the best practices to detect mistakes.
The mistake occurs since podSelector and namespaceSelector can not be "anded" and moreover, namespaceSelector refers to "this" namespace. Thus, two meant to be different rules are actually identical and redundant w.r.t. each other.

* _sanity-typoNotIn-networkpolicy.yaml_ demonstrates the ability of the redundancy and the first good practice rule to detect mistakes; 
the mistake is a typo in the "notIn" podSelector as result of all pods in the namespace are selected.

* _sanity-redundant-dash-networkpolicy.yaml_ is yet another example of the ability of the redundant test to detect mistake
the mistake is a redundant dash when defining ports, as a result of which ingress is open to all; this rule thus makes the other rule in the policy redundant.

##interferes:
The files in the interferes folder demonstrate the ability of interferes to detect mistakes.
A good practice is to execute the test whenever a specific policy/file should exclusively define the connections to and from a given pods set.

The first two policies, interferes-networkpolicy1 and interferes-networkpolicy2 demonstrate a case in which a believed-to-be-empty intersection is not so.
The policies restrict access to specific pods in kube-system.
First policy should be the only one that enables connection to pods with app keepalived-watcher or kube-fluentd.
Second policy, enabling connections to pods with tier frontend, should be disjoint. It should not interfere with the first one.
However, there is a pod in namespace kube-system with tier frontend and also with app keepalived-watcher; thus each policy creates a hole in the other
and specifically the second policy interferes with the first one.

The second two policies, interferes-networkpolicy3 and interferes-networkpolicy4 demonstrate a typo that is revealed with the interferes test.
Both policies restrict incoming traffic to namespace kube-system.
The first enables traffic from pods in namespace default and the second to pods in namespace vendor-system on port 53
Hence, the traffic referred to by these policies should be disjoint and specifically not interfere
But due to a typo in the second policy (redundant -) it allows all traffic on port 53 into kube-system and interferes the first policy.

##regression:
The files in the regression folder demonstrates the ability of the containment and the equivalence tests to detect mistakes done while modifying a file.
A good practice in regression is to have the containment and the equivalence tests on both versions. 

The regression-withIpBlock-old.yaml policy is contained in the regression-withIpBlock-new.yaml since the latter added ipBlocks and ports to the egress rule.
This should be verified with the containment test and with the equivalence test (the latter should fail).

regression-podSelector-old.yaml enables certain communication without restricting the ports for this communication. 
regression-podSelector-new.yaml should restrict the communication only to specific ports 53 and 54
But due to a typo - redundant dash - it actually opens the communication on these ports to all.
Thus, while the new policy should be contained in the old one it contains it; the test reveals the mistake.

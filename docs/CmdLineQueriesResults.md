## Result of a Command-Line Query Run:
The result of each command-line query may be 0 or 1 as followed:

| Query switch | Query Name | meaning of result = 0  | meaning of result = 1 
|--------------|------------|------------------------|----------------------|
| --sanity | Sanity |  passed sanity check | failed sanity check - sanity issues found|
| --equiv | TwoWayContainment | both sets of NetworkPolicies are identical | the sets of NetworkPolicies are not identical |
| --interferes | Interferes | both sets of NetworkPolicies are identical or second set extends the first one | the second set of NetworkPolicies does not interfere with the first set|
| --permits | Permits | both sets of NetworkPolicies are identical or first set contains the other | no containment between the NetworkPolicies |
| --forbids | Forbids | base set of NetworkPolicies forbids the second set | base set of NetworkPolicies does not forbid the second set |
| --connectivity | ConnectivityMap | the result of this query is always 0 | None |
| --semantic_diff | SemanticDiff | both sets of NetworkPolicies are semantically equivalent | the given sets of NetworkPolicies are not semantically equivalent |

## A query will not be executed when:
1. The config/s type is not relevant for performing the query.
2. An input config does not include NetworkPolicies.
3. The input configs are not comparable.
4. The input configs of equivalence/semantic-diff query are identical.

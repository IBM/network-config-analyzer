# Single string dimension
In this experiment we compare `Z3SimpleStringSet` and `MinDFA` on different operations and sets.
We generate random strings, and add them to the set.

In one mode, we just use the strings as an exact match.
In the second mode, we use the strings as a prefix constraint, by adding "\*" at their ends.
In the last mode, we use the strings as a prefix and suffix constraints, for some we add '\*' at the end and for some
we add '\*' at the start.

"""Comparing Z3SimpleStringSet, Z3RegularStringSet and MinDFA for string sets with general regex constraints.
This is relatively quick & dirty experiment for basic comparison of the two sets, and showing that
Z3SimpleStringSet times-out.
"""

import time
from csv import DictWriter
from pathlib import Path

from nca.CoreDS.MinDFA import MinDFA
from experiments.z3_sets.z3_regular_string_set import Z3RegularStringSet
from experiments.z3_sets.z3_simple_string_set import Z3SimpleStringSet


def run_hard_coded_experiment():
    set_types = [Z3SimpleStringSet, Z3RegularStringSet, MinDFA]
    results = {}
    for cls in set_types:
        times = []

        def record_time(operation: str):
            t = time.perf_counter()
            times.append((operation, t))

        record_time('start')
        regex1 = 'aabb'
        s1 = cls.dfa_from_regex(regex1)
        record_time('creation')
        assert 'aabb' in s1
        assert 'abab' not in s1
        record_time('membership')

        regex2 = '(ab)+'
        s2 = cls.dfa_from_regex(regex2)
        record_time('creation')
        assert 'ababab' in s2
        assert 'ababba' not in s2
        record_time('membership')

        regex3 = '(f)?zz(x)*'
        s3 = cls.dfa_from_regex(regex3)
        record_time('creation')
        assert 'zz' in s3
        assert 'ffzzxxx' not in s3
        record_time('membership')

        regex4 = 'abab(ab)*'
        s4 = cls.dfa_from_regex(regex4)
        record_time('creation')
        try:
            assert s4.contained_in(s2)
            record_time('contained_in')
            assert not s1.contained_in(s4)
            record_time('contained_in')
        except TimeoutError:
            print(f'cls {cls.__name__} timed out 1.')

        s5 = s3 | s4  # (f)?zz(x)* | abab(ab)*
        record_time('union')
        assert 'fzzx' in s5
        assert 'abab' in s5
        assert 'ab' not in s5
        record_time('membership')

        regex6 = '(.*)zz(.*)'
        s6 = cls.dfa_from_regex(regex6)
        record_time('creation')
        assert 'blazzxxx' in s6
        assert 'blazkkzxx' not in s6
        record_time('membership')

        s7 = s6 - s3    # (.*)zz(.*) - (f)?zz(x)*
        record_time('subtraction')
        assert 'xzzf' in s7
        assert 'zz' not in s7
        record_time('membership')

        s8 = s5 & s7  # empty set
        record_time('intersection')
        try:
            assert not s8  # s8 is empty
            record_time('contained_in')
        except TimeoutError:
            print(f'cls {cls.__name__} timed out 2.')

        regex9 = '(a*)|(b*)|(a|b)*'
        s9 = cls.dfa_from_regex(regex9)
        record_time('creation')
        assert 'ababbba' in s9
        assert 'abbazab' not in s9
        record_time('membership')
        try:
            assert s1.contained_in(s9)
            record_time('contained_in')
            assert s2.contained_in(s9)
            record_time('contained_in')
            assert s4.contained_in(s9)
            record_time('contained_in')
            assert not s6.contained_in(s9)
            record_time('contained_in')
        except TimeoutError:
            print(f'cls {cls.__name__} timed out 3.')

        regex10 = '((.*)(a|b|z|x)(.*))+'
        s10 = cls.dfa_from_regex(regex10)
        record_time('creation')
        assert 'bjkabsd' in s10
        assert 'jjuq' not in s10
        record_time('membership')
        try:
            assert s2.contained_in(s10)
            record_time('contained_in')
            assert not s9.contained_in(s10)
            record_time('contained_in')
            assert not s10.contained_in(s9)
            record_time('contained_in')
        except TimeoutError:
            print(f'cls {cls.__name__} timed out 4.')

        s11 = ((s9 - s4) | (s6 - s2)) & s10
        record_time('mixed_bool_operation')
        try:
            assert s6.contained_in(s11)
            record_time('contained_in')
        except TimeoutError:
            print(f'cls {cls.__name__} timed out 5.')

        if cls != Z3SimpleStringSet:
            total_time = times[-1][1] - times[0][1]
            per_operation_times = []
            for i in range(len(times) - 1):
                operation, t2 = times[i+1]
                _, t1 = times[i]
                t = t2 - t1
                per_operation_times.append((operation, t))
            results[cls] = {
                'total_time': total_time,
                'per_operation_times': per_operation_times
            }

    # save results in a csv file
    columns = ['operation', 'Z3RegularStringSet', 'MinDFA']
    entries = []
    entries.append({
        'operation': 'total_time',
        'Z3RegularStringSet': results[Z3RegularStringSet]['total_time'],
        'MinDFA': results[MinDFA]['total_time'],
    })
    per_operation_times = zip(
        results[Z3RegularStringSet]['per_operation_times'],
        results[MinDFA]['per_operation_times'],
    )
    for (op1, t1), (op2, t2) in per_operation_times:
        entries.append({
            'operation': op1,
            'Z3RegularStringSet': t1,
            'MinDFA': t2,
        })

    csv_file = Path(__file__).with_stem('hard_coded_times').with_suffix('.csv')
    with csv_file.open('w', newline='') as f:
        writer = DictWriter(f, columns)
        writer.writeheader()
        writer.writerows(entries)


if __name__ == '__main__':
    run_hard_coded_experiment()

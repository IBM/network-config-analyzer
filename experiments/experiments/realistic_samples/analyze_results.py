from contextlib import redirect_stdout
from csv import DictReader, DictWriter
from statistics import variance
# TODO: update this script to support HyperCubeSetDD


def analyze_table(table: list[dict]):
    total_our_time = sum(float(entry['CanonicalHyperCubeSet_time']) for entry in table)
    print(f'total canonical time: {total_our_time}')

    total_z3_time = sum(float(entry['Z3ProductSet_time']) for entry in table)
    print(f'total z3 time: {total_z3_time}')

    max_our_time = max(float(entry['CanonicalHyperCubeSet_time']) for entry in table)
    print(f'max canonical time: {max_our_time}')

    max_z3_time = max(float(entry['Z3ProductSet_time']) for entry in table)
    print(f'max z3 time: {max_z3_time}')

    our_time_var = variance(float(entry['CanonicalHyperCubeSet_time']) for entry in table)
    print(f'canonical time variance: {our_time_var}')

    z3_time_var = variance(float(entry['Z3ProductSet_time']) for entry in table)
    print(f'z3 time variance: {z3_time_var}')

    for entry in table:
        entry['time_diff'] = float(entry['Z3ProductSet_time']) - float(entry['CanonicalHyperCubeSet_time'])

    n_z3_wins = sum(entry['time_diff'] < 0 for entry in table)
    print(f'z3_wins in {n_z3_wins} out of {len(table)}')

    n_entries_to_print = 10
    table_sorted_by_time_diff = sorted(table, key=lambda x: x['time_diff'])
    print('Samples with highest advantage to z3')
    for entry in table_sorted_by_time_diff[:n_entries_to_print]:
        print(f'advantage: {-entry["time_diff"]}, sample: {entry["description"]}')

    print()

    table_sorted_by_time_diff = sorted(table, key=lambda x: x['time_diff'])
    print('Samples with highest advantage to canonical')
    for entry in reversed(table_sorted_by_time_diff[-n_entries_to_print:]):
        print(f'advantage: {entry["time_diff"]}, sample: {entry["description"]}')

    res = {
        '#samples': len(table),
        '#z3 wins': n_z3_wins,
        'z3 wins (%)': n_z3_wins / len(table) * 100,
        'z3 total time': total_z3_time,
        'canonical total time': total_our_time,
        'z3 max time': max_z3_time,
        'canonical max time': max_our_time,
        'z3 variance': z3_time_var,
        'canonical variance': our_time_var,
        'z3 max advantage': -table_sorted_by_time_diff[0]['time_diff'],
        'canonical max advantage': table_sorted_by_time_diff[-1]['time_diff']
    }
    res = {k: round(v, 3) for k, v in res.items()}
    return res


def main():
    # TODO: create a table with summery statistics
    summary_table = []
    # for with_creation in [True, False]:
    for with_creation in [True]:
        for operation in ['contained_in', 'emptiness', 'equivalence']:
            for mode in ['simple', 'complex']:
                if with_creation:
                    filename = f'{operation}+creation_{mode}.csv'
                else:
                    filename = f'{operation}_{mode}.csv'

                with open(filename, 'r') as f:
                    reader = DictReader(f)
                    table = [entry for entry in reader]
                print('=' * 30)
                print(f'analyzing table {filename}')
                summary_row = {'operation': operation, 'mode': mode}
                summary_row.update(analyze_table(table))
                summary_table.append(summary_row)

    with open('summary_table.csv', 'w', newline='') as f:
        writer = DictWriter(f, fieldnames=summary_table[0].keys())
        writer.writeheader()
        writer.writerows(summary_table)


if __name__ == '__main__':
    with open('analysis_output.txt', 'w') as f, redirect_stdout(f):
        main()

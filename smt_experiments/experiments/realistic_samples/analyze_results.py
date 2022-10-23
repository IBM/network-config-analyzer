from contextlib import redirect_stdout

from smt_experiments.experiments.realistic_samples.run_experiment import load_results


def analyze():
    categories = ['creation_and_emptiness', 'equivalence', 'contained_in']
    total_z3_time = 0
    total_canonical_time = 0

    for category in categories:
        print(f'Category={category}.')

        results = load_results(category)
        z3_results = results['Z3ProductSet']
        canonical_results = results['CanonicalHyperCubeSet']

        # figure out in each category, how much times z3 wins ours and vice versa.
        z3_wins_counter = 0
        for z3_res, canonical_res in zip(z3_results, canonical_results):
            if z3_res['time'] < canonical_res['time']:
                z3_wins_counter += 1
        print(f'Z3 wins {z3_wins_counter} times out of {len(z3_results)}.')

        # find the most extreme examples of differences between z3 and our implementation.
        top_z3_positive_diff_i = None
        top_z3_positive_diff = None
        top_z3_negative_diff_i = None
        top_z3_negative_diff = None

        for i in range(len(z3_results)):
            z3_res = z3_results[i]
            canonical_res = canonical_results[i]
            diff = canonical_res['time'] - z3_res['time']
            if diff > 0:
                if top_z3_positive_diff_i is None or diff > top_z3_positive_diff:
                    top_z3_positive_diff_i = i
                    top_z3_positive_diff = diff
            else:
                diff = -diff
                if top_z3_negative_diff_i is None or diff > top_z3_negative_diff:
                    top_z3_negative_diff_i = i
                    top_z3_negative_diff = diff
        if top_z3_positive_diff_i is not None:
            print(f'The top positive difference for z3 is {top_z3_positive_diff:.3f} '
                  f'at index {top_z3_positive_diff_i}.')
        if top_z3_negative_diff_i is not None:
            print(f'The top negative difference for z3 is {top_z3_negative_diff:.3f} '
                  f'at index {top_z3_negative_diff_i}.')

        # for each category, compute the total for z3 and our.
        total_z3_time_per_category = 0
        total_canonical_time_per_category = 0
        for z3_res, canonical_res in zip(z3_results, canonical_results):
            total_z3_time_per_category += z3_res['time']
            total_canonical_time_per_category += canonical_res['time']
        print(f'Total time for Z3ProductSet in this category is {total_z3_time_per_category:.3f}.')
        print(f'Total time for CanonicalHyperCubeSet in this category is {total_canonical_time_per_category:.3f}.')
        total_z3_time += total_z3_time_per_category
        total_canonical_time += total_canonical_time_per_category
        print()

    # for all the categories, compute the total time for z3 and ours.
    print(f'Total time for Z3ProductSet for all categories is {total_z3_time:.3f}.')
    print(f'Total time for CanonicalHyperCubeSet for all categories is {total_canonical_time:.3f}.')


if __name__ == '__main__':
    with open('analyze_results_output.txt', 'w') as f, redirect_stdout(f):
        analyze()

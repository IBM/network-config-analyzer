from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from smt_experiments.experiments.realistic_samples.connection_attributes_list import CONNECTION_ATTR_LIST
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet

# TODO: compare the output of the tools and make sure that they align.
"""Experiment design:
- We start with a set of connection attributes.
- We create sets of configurations, which is a set of allow and deny subsets.
- For each of those configurations, we construct it, and check emptiness. 
    This is the first data point.
- For each pair of configurations, we check equivalence, and containment for each side.
    This is the second data point.
"""
"""Presenting the results:
- I want to somehow order the samples, maybe on their hyper-cube-set creation time.
- graph for creation and emptiness check.
- graph with the containment checks time for each pair.
- graph with equivalence check times.
- table with all the results.
"""


def get_all_dims():
    return ['peers', 'src_ports', 'dst_ports', 'methods', 'paths', 'hosts']


def containment_checks():
    connection_sets = []
    all_dims = get_all_dims()
    for connection_attr in CONNECTION_ATTR_LIST:
        cube, dims = connection_attr.to_canonical_cube()
        s = CanonicalHyperCubeSet.create_from_cube(all_dims, cube, dims)
        connection_sets.append(s)

    results = []
    for i in range(len(connection_sets)):
        for j in range(i+1, len(connection_sets)):
            print(i, j)
            out1 = connection_sets[i].contained_in(connection_sets[j])
            out2 = connection_sets[j].contained_in(connection_sets[i])
            results.append(out1)
            results.append(out2)


def construct_all_cubes():
    all_dims = get_all_dims()
    s = CanonicalHyperCubeSet(all_dims)
    for i, connection_attr in enumerate(CONNECTION_ATTR_LIST, 1):
        print(f'adding cube {i} out of {len(CONNECTION_ATTR_LIST)}.')
        cube, dims = connection_attr.to_canonical_cube()
        s.add_cube(cube, dims)
    for cube in s:
        print(cube)


def run_experiment():
    cls_list = [CanonicalHyperCubeSet, Z3ProductSet]

    for cls in cls_list:
        # TODO:
        pass


if __name__ == '__main__':
    containment_checks()


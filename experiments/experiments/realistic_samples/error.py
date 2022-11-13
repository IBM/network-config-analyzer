from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.MinDFA import MinDFA
from decision_diagram.hyper_cube_set_dd import HyperCubeSetDD


def possible_bug():
    dims = ['dst_ports', 'hosts']
    cube1 = [CanonicalIntervalSet.get_interval_set(10, 20)]
    dims1 = ['dst_ports']
    cube2 = [MinDFA.from_wildcard('example.com')]  # the '.' here is important for the bug, otherwise it does not occur
    dims2 = ['hosts']

    # With HyperCubeSetDD, this works as expected:
    s1 = HyperCubeSetDD(dims)
    s1.add_cube(cube1, dims1)

    s2 = HyperCubeSetDD(dims)
    s2.add_cube(cube1, dims1)
    s2.add_cube(cube2, dims2)

    res = s1.contained_in(s2)
    assert res, "HyperCubeSetDD"

    # with CanonicalHyperCubeSet, there seems to be some strange behaviour
    s1 = CanonicalHyperCubeSet(dims)
    s1.add_cube(cube1, dims1)

    s2 = CanonicalHyperCubeSet(dims)
    s2.add_cube(cube1, dims1)
    s2.add_cube(cube2, dims2)

    res = s1.contained_in(s2)
    assert res, "CanonicalHyperCubeSet"  # This assertion fails


if __name__ == '__main__':
    possible_bug()

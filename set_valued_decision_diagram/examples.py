from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.DimensionsManager import DimensionsManager


def Interval(start: int, end: int):
    return CanonicalIntervalSet.get_interval_set(start, end)


def example1():
    """This is an example of merging identical subtrees."""
    dim_names = init_dims()
    s = CanonicalHyperCubeSet(dim_names)
    cubes = [
        [Interval(1, 10), Interval(1, 10), Interval(1, 10)],
        [Interval(1, 10), Interval(20, 30), Interval(1, 10)],
        [Interval(20, 30), Interval(1, 10), Interval(1, 10)],
        [Interval(20, 30), Interval(20, 30), Interval(20, 30)]
    ]
    for cube in cubes:
        s.add_cube(cube)
    print(s)


def init_dims():
    dim_manager = DimensionsManager()
    dim_names = ['x', 'y', 'z']
    for dim_name in dim_names:
        dim_manager.set_domain(dim_name, dim_manager.DimensionType.IntervalSet)
    return dim_names


def example2():
    """This is an example where we have dont-care node in the middle of the tree."""
    dim_names = init_dims()
    s = CanonicalHyperCubeSet(dim_names)
    s.add_cube([Interval(1, 10), Interval(1, 10)], ['x', 'z'])
    s.add_cube([Interval(1, 10), Interval(20, 30)], ['x', 'z'])
    s.add_cube([Interval(20, 30), Interval(1, 10), Interval(1, 10)])
    s.add_cube([Interval(20, 30), Interval(20, 30), Interval(20, 30)])
    print(s)


if __name__ == '__main__':
    example2()

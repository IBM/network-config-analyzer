import string
import timeit

from CanonicalIntervalSet import CanonicalIntervalSet
from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from DimensionsManager import DimensionsManager
from z3 import *


dim_manager = DimensionsManager()


def create_z3_vars(var_names):
    vars_res = []
    vars_dict = dict()
    for n in var_names:
        z3_v = Int(n)
        vars_res.append(z3_v)
        vars_dict[n] = z3_v
    return vars_res, vars_dict


def get_z3_cube(cube_intervals, cube_vars, all_vars, default_interval, vars_dict):
    res = None
    for index, interval in enumerate(cube_intervals):
        z3_var = vars_dict[cube_vars[index]]
        if res is None:
            res = z3.And(z3_var >= interval.start, z3_var <= interval.end)
        else:
            res = z3.And(res, z3_var >= interval.start, z3_var <= interval.end)
    default_vars = set(all_vars) - set(cube_vars)
    for var_name in default_vars:
        z3_var = vars_dict[var_name]
        res = z3.And(res, z3_var >= default_interval.start, z3_var <= default_interval.end)
    return res


def z3_test(cube1, cube2):
    # return if cube1 is contained in cube2
    solver = z3.Solver()
    solver.add(z3.And(cube1, z3.Not(cube2)))  # unsat -> anything in cube 1 is also in cube 2
    result = solver.check()
    if str(result) == 'unsat':
        return True
    assert(str(result) == 'sat')
    return False


def get_cubes_set_z3(cubes_list):
    res = cubes_list[0]
    for cube in cubes_list[1:]:
        res = z3.Or(res, cube)
    return res


def cube_test_1_z3(num_dims):
    chars = list(string.ascii_lowercase)
    var_names = chars[0:20]
    z3_vars, vars_dict = create_z3_vars(var_names)
    cube_intervals = [CanonicalIntervalSet.Interval(1,20), CanonicalIntervalSet.Interval(1,20)]
    cube_vars = ['a', 'b']
    cube1 = get_z3_cube(cube_intervals, cube_vars, var_names, CanonicalIntervalSet.Interval(1,100000), vars_dict)
    cube2 = get_z3_cube([CanonicalIntervalSet.Interval(15,40)], ['b'], var_names, CanonicalIntervalSet.Interval(1,100000), vars_dict)
    cubes_set = get_cubes_set_z3([cube1, cube2])
    sub_cube = get_z3_cube([CanonicalIntervalSet.Interval(1,5)]*20, var_names, var_names, CanonicalIntervalSet.Interval(1,100000), vars_dict)
    cube_intervals_new = [CanonicalIntervalSet.Interval(100,200), CanonicalIntervalSet.Interval(300,400)]
    for i in range(1, num_dims):
        cube_vars = [var_names[i], var_names[i + 1]]
        cube_to_add =  get_z3_cube(cube_intervals_new, cube_vars, var_names, CanonicalIntervalSet.Interval(1,100000), vars_dict)
        cubes_set_new = get_cubes_set_z3([cubes_set, cube_to_add])
        z3_test(sub_cube, cubes_set_new)
        w = cube_intervals_new[0]
        y = cube_intervals_new[1]
        w.start += 200
        w.end += 200
        y.start += 200
        y.end += 200
        cube_intervals_new = [CanonicalIntervalSet.Interval(w.start, w.end), CanonicalIntervalSet.Interval(y.start, y.end)]


def cubes_test_1(num_dims):
    chars = list(string.ascii_lowercase)
    dim_names = chars[0:20]
    interval_domain_object = CanonicalIntervalSet.get_interval_set(1, 100000)
    dim_domains_values = dict()
    for n in dim_names:
        dim_domains_values[n] = interval_domain_object
        dim_manager.set_domain(n, DimensionsManager.DimensionType.IntervalSet, (1, 100000))
    dimensions_new = dim_names
    x = CanonicalHyperCubeSet(dimensions_new)
    a1 = CanonicalIntervalSet.get_interval_set(1, 20)
    x.add_cube([a1, a1], ["a", "b"])
    a2 = CanonicalIntervalSet.get_interval_set(15, 40)
    x.add_cube([a2], ["b"])
    cube = [CanonicalIntervalSet.get_interval_set(100, 200), CanonicalIntervalSet.get_interval_set(300, 400)]
    x_sub_cube = CanonicalHyperCubeSet(dimensions_new)
    sub_range = CanonicalIntervalSet.get_interval_set(1, 5)
    x_sub_cube.add_cube([sub_range]*20, dim_names)
    for i in range(1, num_dims):
        cube_dims = [dim_names[i], dim_names[i + 1]]
        x.add_cube(cube, cube_dims)
        res = x_sub_cube.contained_in(x)
        w = next(iter(cube[0]))
        y = next(iter(cube[1]))
        w.start += 200
        w.end += 200
        y.start += 200
        y.end += 200
        cube = [CanonicalIntervalSet.get_interval_set(w.start, w.end),
                CanonicalIntervalSet.get_interval_set(y.start, y.end)]


for num_dims in range(2, 18):
    start1 = timeit.default_timer()
    cubes_test_1(num_dims)
    stop1 = timeit.default_timer()
    cube_test_1_z3(num_dims)
    stop2 = timeit.default_timer()
    print(f'{stop1 - start1}, {stop2-stop1}, {num_dims}')

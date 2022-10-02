import unittest
from unittest import skip

from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet as CanonicalIntervalSet
from smt_experiments.z3_sets.z3_simple_string_set import Z3SimpleStringSet as MinDFA
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet as CanonicalHyperCubeSet
from DimensionsManager import DimensionsManager

dimensions = ["src_ports", "ports", "methods_dfa", "paths"]
dimensions2 = ["ports", "src_ports", "methods_dfa", "paths"]
dimensions3 = ["src_ports", "ports", "methods_dfa", "paths", "hosts"]
dimensions4 = ["x", "y", "z"]
dim_manager = DimensionsManager()
dim_manager.set_domain("methods_dfa", DimensionsManager.DimensionType.DFA)
dim_manager.set_domain("ports", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
dim_manager.set_domain("x", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
dim_manager.set_domain("y", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
dim_manager.set_domain("z", DimensionsManager.DimensionType.IntervalSet, (1, 65535))


def get_str_dfa(s):
    return MinDFA.from_wildcard(s)


class TestCanonicalHyperCubeSetMethods(unittest.TestCase):
    """
    unit tests for CanonicalHyperCubeSet with methods_dfa dimension of type DFA.
    """

    @skip('Nothing is tested here.')
    def test_dfa_equality(self):
        dfa_all = dim_manager.get_dimension_domain_by_name("methods_dfa")
        dfa_all.is_all_words = MinDFA.Ternary.UNKNOWN
        dfa_put = get_str_dfa("PUT")
        dfa_put_2 = dfa_put & dfa_all
        # print(dfa_all.get_fsm_str())
        print(dfa_put.get_fsm_str())
        print(dfa_put_2.get_fsm_str())
        # super().__init__(alphabet, states, initial, finals, map)
        print(dfa_put.fsm.alphabet == dfa_put_2.fsm.alphabet)
        print(dfa_put.fsm.states == dfa_put_2.fsm.states)
        print(dfa_put.fsm.initial == dfa_put_2.fsm.initial)
        print(dfa_put.fsm.finals == dfa_put_2.fsm.finals)
        print(dfa_put.fsm.map == dfa_put_2.fsm.map)

    # FOR TRACE DEMO
    def test_create_from_cube(self):
        s = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("PUT")], ["methods_dfa"])
        print(s)
        ports_range = CanonicalIntervalSet.get_interval_set(100, 200)
        methods_dfa = get_str_dfa("PUT")
        cube2 = [ports_range, methods_dfa]
        x = CanonicalHyperCubeSet.create_from_cube(dimensions, cube2, ["ports", "methods_dfa"])
        print(x)

    @skip('build_new_active_dimensions method not supported.')
    def test_set_active_dims_new(self):
        x = CanonicalHyperCubeSet(dimensions3)
        x.add_cube([get_str_dfa("PUT")], ["methods_dfa"])
        print(x)
        x.build_new_active_dimensions(["ports", "methods_dfa", "paths", "hosts"])
        print(x)

    @skip('build_new_active_dimensions method not supported.')
    def test_remove_active_dims_new(self):
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube([get_str_dfa("PUT")], ["methods_dfa"])
        x.build_new_active_dimensions(["ports", "methods_dfa", "paths", "hosts"])
        y = x.copy()
        z = x.copy()
        print(x)
        x._remove_some_active_dimensions(["methods_dfa", "paths", "hosts"])
        y._remove_some_active_dimensions(["methods_dfa"])
        z._remove_some_active_dimensions(["ports", "methods_dfa"])
        print(x)
        print(y)
        print(z)

    @skip('_set_active_dimensions method not supported.')
    def test_set_active_dimensions(self):
        x = CanonicalHyperCubeSet.create_from_cube(dimensions3, [get_str_dfa("PUT"), get_str_dfa("abc")],
                                                   ["methods_dfa", "paths"])
        print(x)
        x._set_active_dimensions({"methods_dfa"})
        print(x)
        x._set_active_dimensions({"methods_dfa", "paths"})
        print(x)
        x._set_active_dimensions({"methods_dfa", "paths", "hosts"})
        print(x)
        x._set_active_dimensions({"methods_dfa", "paths", "hosts", "ports"})
        print(x)

    @skip('_get_cubes_list_from_layers method not supported.')
    def test_basic_1(self):
        """
        test methods: __eq__ , __bool__ , __str__, add_cube
        objects: empty, all,  and some obj with cubes
        """
        # new empty object
        x = CanonicalHyperCubeSet(dimensions)
        self.assertFalse(x)
        self.assertEqual(str(x), "Empty")
        # new "allow all" object
        y = CanonicalHyperCubeSet(dimensions, True)
        self.assertTrue(y)
        self.assertEqual(str(y), "All")
        self.assertEqual(x, x)

        new_active_dimensions = ["ports", "methods_dfa"]
        ports_range = CanonicalIntervalSet.get_interval_set(1, 20)
        methods_dfa = get_str_dfa("GET")
        cube = [ports_range, methods_dfa]
        x.add_cube(cube, new_active_dimensions)
        self.assertEqual(x._get_cubes_list_from_layers(), [cube])

        ports_range = CanonicalIntervalSet.get_interval_set(100, 200)
        methods_dfa = get_str_dfa("PUT")
        cube2 = [ports_range, methods_dfa]
        x.add_cube(cube2, new_active_dimensions)
        self.assertEqual(x._get_cubes_list_from_layers(), [cube, cube2])
        self.assertTrue(x)
        self.assertEqual(x, x)
        self.assertEqual(y, y)
        self.assertNotEqual(x, y)
        self.assertNotEqual(y, x)

    def test_basic_2(self):
        """
        test methods: __eq__ , add_cube, add_hole, __sub__
        objects: empty, all,  and some obj with cubes
        """
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions, True)
        self.assertNotEqual(x, y)  # y is all, x is empty
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_str_dfa("GET")
        cube = [ports_range, methods_dfa]
        x.add_cube(cube, ["ports", "methods_dfa"])  # is now equals this cube
        y.add_cube(cube, ["ports", "methods_dfa"])  # y remains all
        self.assertNotEqual(x, y)

        z = CanonicalHyperCubeSet(dimensions, True)
        z.add_hole(cube, ["ports", "methods_dfa"])  # z should be the complement of x
        self.assertNotEqual(x, z)
        self.assertNotEqual(z, y)
        # res_tmp = x | z
        # print(res_tmp)
        # print(y)
        self.assertEqual(x | z, y)
        empty = CanonicalHyperCubeSet(dimensions)
        all = CanonicalHyperCubeSet(dimensions, True)
        new_empty = all - all
        self.assertEqual(new_empty, empty)
        self.assertEqual(all, y)

    @skip('active_dimensions not supported.')
    def test_basic_3(self):
        """
        test basic case for correctness of reduce_active_dimensions
        """
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        z = CanonicalHyperCubeSet(dimensions, True)
        methods_dfa1 = dim_manager.get_dimension_domain_by_name("methods_dfa") - get_str_dfa("a")
        methods_dfa2 = get_str_dfa("a")
        x.add_cube([methods_dfa1], ["methods_dfa"])
        y.add_cube([methods_dfa2], ["methods_dfa"])
        w = x | y
        self.assertEqual(x.active_dimensions, ["methods_dfa"])
        self.assertEqual(y.active_dimensions, ["methods_dfa"])
        self.assertEqual(w.active_dimensions, [])
        self.assertEqual(z.active_dimensions, [])
        self.assertEqual(w, z)

    @skip('__eq__ only supports the same type for other.')
    def test_eq_basic(self):
        x = CanonicalHyperCubeSet(dimensions)
        self.assertNotEqual("s", x)
        # TODO: test Dimensions __eq__ ?
        y = CanonicalHyperCubeSet(dimensions2)
        self.assertNotEqual(y, x)

    @skip('__len__ is not supported.')
    def test_len_basic(self):
        all = CanonicalHyperCubeSet(dimensions, True)
        empty = CanonicalHyperCubeSet(dimensions)
        x1 = empty.copy()
        x1.add_cube([get_str_dfa("a")], ["methods_dfa"])
        x2 = empty.copy()
        x2.add_cube([get_str_dfa("b")], ["paths"])
        x2.add_cube([get_str_dfa("a")], ["methods_dfa"])
        # print(x1)
        # print(x2)
        self.assertEqual(len(all), 1)
        self.assertEqual(len(empty), 0)
        self.assertEqual(len(x1), 1)
        self.assertEqual(len(x2), 2)

    @skip('__hash__ is not supported.')
    def test_hash_basic(self):
        d = dict()
        all1 = CanonicalHyperCubeSet(dimensions, True)
        empty1 = CanonicalHyperCubeSet(dimensions)
        x1 = empty1.copy()
        x1.add_cube([get_str_dfa("a")], ["methods_dfa"])
        not_x1 = all1 - x1
        empty2 = x1 - x1
        all2 = not_x1 | x1
        # print(empty2.active_dimensions)
        # print(empty1.active_dimensions)
        d[empty2] = "empty"
        d[all1] = "all"
        d[x1] = "x1"
        self.assertEqual(d[empty1], d[empty2])
        self.assertEqual(d[all1], d[all2])
        self.assertEqual(d[x1], d[all1 - not_x1])

    def test_reduce_active_dimensions(self):
        x = CanonicalHyperCubeSet(dimensions)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_str_dfa("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_dfa]
        ports_rang2 = CanonicalIntervalSet.get_interval_set(100, 200)
        cube2 = [ports_rang2, methods_dfa, paths_dfa]
        x.add_cube(cube1, ["ports", "methods_dfa"])
        # print(x)
        y = x.copy()
        x.add_hole(cube2, ["ports", "methods_dfa", "paths"])
        # print(x)
        # print(y)
        self.assertEqual(x, y)

    def test_reduce_active_dimensions_2(self):
        x = CanonicalHyperCubeSet(dimensions)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_str_dfa("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_dfa]
        ports_rang2 = CanonicalIntervalSet.get_interval_set(100, 200)
        cube2 = [ports_rang2, methods_dfa, paths_dfa]
        cube3 = [CanonicalIntervalSet.get_interval_set(500, 600)]
        x.add_cube(cube1, ["ports", "methods_dfa"])
        x.add_cube(cube3, ["ports"])
        y = CanonicalHyperCubeSet(dimensions)
        y.add_cube(cube2, ["ports", "methods_dfa", "paths"])
        y.add_cube(cube3, ["ports"])
        w = CanonicalHyperCubeSet(dimensions)
        w.add_cube(cube3, ["ports"])
        z = x & y
        # print(x)
        # print(y)
        # print(z)
        # print(z.active_dimensions)
        # print(w)
        self.assertEqual(z, w)

    @skip('full regex is not supported.')
    def test_canonical_rep_dfa_new(self):
        dfa1 = get_str_dfa("[ab]*")
        dfa2 = get_str_dfa("[bc]*")
        dfa3 = get_str_dfa("[ac]*")
        dfa4 = get_str_dfa("a")
        dfa5 = get_str_dfa("b")
        dfa6 = get_str_dfa("c")

        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)

        x.add_cube([dfa1, dfa4], ["methods_dfa", "paths"])
        # print(f'x1: {x}')
        x.add_cube([dfa2, dfa5], ["methods_dfa", "paths"])
        # print(f'x2: {x}')
        x.add_cube([dfa3, dfa6], ["methods_dfa", "paths"])
        # print(f'x3: {x}')
        # print(x)

        y.add_cube([dfa2, dfa5], ["methods_dfa", "paths"])
        # print(f'y1: {y}')
        y.add_cube([dfa3, dfa6], ["methods_dfa", "paths"])
        # print(f'y2: {y}')
        y.add_cube([dfa1, dfa4], ["methods_dfa", "paths"])
        # print(f'y3: {y}')
        # print(y)
        self.assertEqual(x, y)

    def test_canonical_rep_dfa_new_1(self):
        dfa1 = get_str_dfa("ab|bc")
        dfa2 = get_str_dfa("bc|ac")
        dfa3 = get_str_dfa("ac|ab")
        dfa4 = get_str_dfa("a")
        dfa5 = get_str_dfa("b")
        dfa6 = get_str_dfa("c|a|b")

        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)

        x.add_cube([dfa1, dfa4], ["methods_dfa", "paths"])
        # print(f'x1: {x}')
        x.add_cube([dfa2, dfa5], ["methods_dfa", "paths"])
        # print(f'x2: {x}')
        x.add_cube([dfa3, dfa6], ["methods_dfa", "paths"])
        # print(f'x3: {x}')
        # print(x)

        y.add_cube([dfa2, dfa5], ["methods_dfa", "paths"])
        # print(f'y1: {y}')
        y.add_cube([dfa3, dfa6], ["methods_dfa", "paths"])
        # print(f'y2: {y}')
        y.add_cube([dfa1, dfa4], ["methods_dfa", "paths"])
        # print(f'y3: {y}')
        # print(y)
        self.assertEqual(x, y)

    @skip('full regex is not supported.')
    def test_canonical_rep_dfa_new_2(self):
        dfa1 = get_str_dfa("a[a]+")
        dfa1_s = get_str_dfa("b")
        dfa2 = get_str_dfa("b[b]+")
        dfa2_s = get_str_dfa("c")
        dfa3 = get_str_dfa("a|b")
        dfa3_s = get_str_dfa("b|c")
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube([dfa1, dfa1_s], ["methods_dfa", "paths"])
        x.add_cube([dfa2, dfa2_s], ["methods_dfa", "paths"])
        x.add_cube([dfa3, dfa3_s], ["methods_dfa", "paths"])
        # print(x)

        dfa4 = get_str_dfa("[a]+|b")
        dfa4_s = get_str_dfa("b")
        dfa5 = get_str_dfa("[b]+|a")
        dfa5_s = get_str_dfa("c")
        y = CanonicalHyperCubeSet(dimensions)
        y.add_cube([dfa4, dfa4_s], ["methods_dfa", "paths"])
        y.add_cube([dfa5, dfa5_s], ["methods_dfa", "paths"])
        # print(y)
        self.assertEqual(x, y)

    @skip('full regex is not supported.')
    def test_empty_dfa_new(self):
        methods_dfa = get_str_dfa("[a]*")
        methods_dfa2 = get_str_dfa("[ab]*")
        m = CanonicalHyperCubeSet(dimensions)
        # n = CanonicalHyperCubeSet(dimensions)
        m.add_cube([methods_dfa], ["methods_dfa"])
        m.add_hole([methods_dfa2], ["methods_dfa"])
        self.assertEqual(m, CanonicalHyperCubeSet(dimensions))
        # print(m)

    @skip('active_dimensions not supported.')
    def test_intersection(self):
        methods_dfa = get_str_dfa("PUT")
        cube3 = [CanonicalIntervalSet.get_interval_set(500, 600)]
        m = CanonicalHyperCubeSet(dimensions)
        n = CanonicalHyperCubeSet(dimensions)
        cube4 = [methods_dfa]
        m.add_cube(cube4, ["methods_dfa"])
        n.add_cube(cube4, ["methods_dfa"])
        m.add_cube(cube3, ["ports"])
        # print(m)
        # print(n)
        k = m & n
        # print(k)
        self.assertEqual(k.active_dimensions, ["methods_dfa"])
        self.assertEqual(k, n)
        self.assertNotEqual(k, m)
        self.assertNotEqual(n, m)

    @skip('__len__ is not supported.')
    def test_add_cube_new(self):
        paths_dfa = get_str_dfa("abc")
        methods_dfa1 = get_str_dfa("PUT")
        methods_dfa2 = get_str_dfa("GET")
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube([methods_dfa1, paths_dfa], ["methods_dfa", "paths"])
        self.assertEqual(1, len(x))
        x.add_cube([methods_dfa2, paths_dfa], ["methods_dfa", "paths"])
        self.assertEqual(1, len(x))
        p = CanonicalIntervalSet.get_interval_set(500, 600)
        y = CanonicalHyperCubeSet(dimensions)
        y.add_cube([p, methods_dfa1, paths_dfa], ["ports", "methods_dfa", "paths"])
        y.add_cube([p, methods_dfa2, paths_dfa], ["ports", "methods_dfa", "paths"])
        self.assertEqual(1, len(y))
        z = y.copy()
        paths_dfa2 = get_str_dfa("bcd")
        y.add_cube([paths_dfa2], ["paths"])
        # print(y)
        self.assertEqual(3, len(y))

    # def test_intersection_2(self):

    def test_add_interval_item(self):
        x = CanonicalHyperCubeSet(dimensions)
        p1 = CanonicalIntervalSet.get_interval_set(10, 20)
        p2 = CanonicalIntervalSet.get_interval_set(1, 2)
        x.add_cube([p1], ["ports"])
        x.add_cube([p2], ["ports"])
        y1 = CanonicalHyperCubeSet(dimensions)
        y2 = CanonicalHyperCubeSet(dimensions)
        y1.add_cube([p1], ["ports"])
        y2.add_cube([p2], ["ports"])
        self.assertEqual(x, y1 | y2)
        hole1 = [CanonicalIntervalSet.get_interval_set(8, 15)]
        hole2 = [CanonicalIntervalSet.get_interval_set(19, 21)]
        x.add_hole(hole1, ["ports"])
        x.add_hole(hole2, ["ports"])
        p3 = CanonicalIntervalSet.get_interval_set(16, 18)
        res = CanonicalHyperCubeSet(dimensions)
        res.add_cube([p2], ["ports"])
        res.add_cube([p3], ["ports"])
        self.assertEqual(res, x)
        # print(x)
        # print(res)

    # TODO: explore exponential blow-up !
    @skip('_get_cubes_list_from_layers not supported.')
    def test_add_cube(self):
        x = CanonicalHyperCubeSet(dimensions)

        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        # x.add_cube([ports_range], ["ports"])
        x.add_cube([ports_range, ports_range], ["src_ports", "ports"])
        # print(x)
        x_expected_cubes = [[ports_range, ports_range]]
        # self.assertEqual(x.cubes_list, x_expected_cubes)
        self.assertEqual(x._get_cubes_list_from_layers(), x_expected_cubes)
        # get_cubes_list_from_layers
        ports_range2 = CanonicalIntervalSet.get_interval_set(15, 40)
        x.add_cube([ports_range2], ["ports"])
        range1 = CanonicalIntervalSet.get_interval_set(1, 9)
        range1 |= CanonicalIntervalSet.get_interval_set(21, 65535)
        x_expected_cubes = [[range1, ports_range2],
                            [ports_range, CanonicalIntervalSet.get_interval_set(10, 40)]]
        self.assertEqual(sorted(x._get_cubes_list_from_layers()), sorted(x_expected_cubes))
        # print(x)

        ports_range3 = CanonicalIntervalSet.get_interval_set(100, 200)
        methods_dfa = get_str_dfa("PUT")
        x.add_cube([ports_range3, methods_dfa], ["ports", "methods_dfa"])
        x_expected_cubes = [
            [range1, ports_range2, dim_manager.get_dimension_domain_by_name("methods_dfa")],
            [range1, ports_range3, methods_dfa],
            [ports_range, CanonicalIntervalSet.get_interval_set(10, 40),
             dim_manager.get_dimension_domain_by_name("methods_dfa")],
            [ports_range, ports_range3, methods_dfa]
        ]
        self.assertEqual(sorted(x._get_cubes_list_from_layers()), sorted(x_expected_cubes))

        paths_dfa = get_str_dfa("abc")
        x._set_active_dimensions({"paths"})
        # self.assertEqual(str(x), x_str_expected_new)
        for cube in x_expected_cubes:
            cube.append(dim_manager.get_dimension_domain_by_name("paths"))
        self.assertEqual(sorted(x._get_cubes_list_from_layers()), sorted(x_expected_cubes))
        # print(x)
        # print(ports_range)
        # print(methods_dfa)
        # print(paths_dfa)

        x.add_cube([ports_range, methods_dfa, paths_dfa], ["ports", "methods_dfa", "paths"])
        x_expected_cubes.append([range1, CanonicalIntervalSet.get_interval_set(10, 14), methods_dfa, paths_dfa])
        # print(x)
        self.assertEqual(sorted(x._get_cubes_list_from_layers()), sorted(x_expected_cubes))

        ports_range4 = CanonicalIntervalSet.get_interval_set(4000, 4000)
        x.add_cube([ports_range4, methods_dfa, paths_dfa], ["ports", "methods_dfa", "paths"])
        for cube in x_expected_cubes:
            if cube == [range1, CanonicalIntervalSet.get_interval_set(10, 14), methods_dfa, paths_dfa]:
                cube[1].add_interval(CanonicalIntervalSet.Interval(4000, 4000))
        x_expected_cubes.append([ports_range, ports_range4, methods_dfa, paths_dfa])
        self.assertEqual(sorted(x._get_cubes_list_from_layers()), sorted(x_expected_cubes))
        # print(x)

        # TODO: test union for resulting cubes, by adding the missing sub-cube
        methods_dfa_all_but_put = dim_manager.get_dimension_domain_by_name("methods_dfa") - methods_dfa
        new_cube = [methods_dfa_all_but_put]
        x.add_cube(new_cube, ["methods_dfa"])
        # x_str_expected_new_3 = "src_ports,ports,methods,paths: ([1-9], [1-14], all but {'PUT'}, *, ),([1-9], [15-40], *, *, ),([1-9], [41-99], all but {'PUT'}, *, ),([1-9], [100-200], *, *, ),([1-9], [201-3999], all but {'PUT'}, *, ),([1-9], [4000-4000], {'PUT'}, {'abc'}, ),([1-9], [4000-4000], all but {'PUT'}, *, ),([1-9], [4001-65535], all but {'PUT'}, *, ),([10-20], [1-9], all but {'PUT'}, *, ),([10-20], [10-40], *, *, ),([10-20], [41-99], all but {'PUT'}, *, ),([10-20], [100-200], *, *, ),([10-20], [201-3999], all but {'PUT'}, *, ),([10-20], [4000-4000], {'PUT'}, {'abc'}, ),([10-20], [4000-4000], all but {'PUT'}, *, ),([10-20], [4001-65535], all but {'PUT'}, *, ),([21-65535], [1-14], all but {'PUT'}, *, ),([21-65535], [15-40], *, *, ),([21-65535], [41-99], all but {'PUT'}, *, ),([21-65535], [100-200], *, *, ),([21-65535], [201-3999], all but {'PUT'}, *, ),([21-65535], [4000-4000], {'PUT'}, {'abc'}, ),([21-65535], [4000-4000], all but {'PUT'}, *, ),([21-65535], [4001-65535], all but {'PUT'}, *, )"
        range2 = CanonicalIntervalSet.get_interval_set(10, 14) | CanonicalIntervalSet.get_interval_set(4000, 4000)
        range3 = CanonicalIntervalSet.get_interval_set(15, 40) | CanonicalIntervalSet.get_interval_set(100, 200)
        range4 = CanonicalIntervalSet.get_interval_set(1, 9) | CanonicalIntervalSet.get_interval_set(41,
                                                                                                     99) | CanonicalIntervalSet.get_interval_set(
            201, 3999) | CanonicalIntervalSet.get_interval_set(4001, 65535)
        range5 = CanonicalIntervalSet.get_interval_set(10, 40) | CanonicalIntervalSet.get_interval_set(100, 200)
        '''
        x_expected_cubes = [
            [range1, range2, methods_dfa, paths_dfa],
            [range1, range2, methods_dfa_all_but_put, dim_domains_values["paths"]],
            [range1, range3, dim_domains_values["methods_dfa"], dim_domains_values["paths"] ],
            [range1, range4, methods_dfa_all_but_put, dim_domains_values["paths"]  ],
            [ports_range, range5, dim_domains_values["methods_dfa"], dim_domains_values["paths"] ],
            [ports_range, ports_range4, methods_dfa_all_but_put, dim_domains_values["paths"] ],
            [ports_range, range4, methods_dfa_all_but_put, dim_domains_values["paths"] ],
            [ports_range, ports_range4, get_str_dfa("PUT"), paths_dfa]
             ]
        '''
        x_expected_cubes = {
            tuple([range1, range2, methods_dfa, paths_dfa]),
            tuple([range1, range2, methods_dfa_all_but_put, dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([range1, range3, dim_manager.get_dimension_domain_by_name("methods_dfa"),
                   dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([range1, range4, methods_dfa_all_but_put, dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, range5, dim_manager.get_dimension_domain_by_name("methods_dfa"),
                   dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, ports_range4, methods_dfa_all_but_put,
                   dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, range4, methods_dfa_all_but_put, dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, ports_range4, get_str_dfa("PUT"), paths_dfa])
        }
        # print(x)
        x_actual_cubes = set(tuple(c) for c in x._get_cubes_list_from_layers())
        self.assertEqual(x_actual_cubes, x_expected_cubes)
        '''
        p1 = sorted(x.cubes_list)
        p2 = sorted(x_expected_cubes)
        print('-------------------------------------')
        self.print_cubes_list(p1)
        print('-------------------------------------')
        self.print_cubes_list(p2)
        print('-------------------------------------')
        for i in range(0,4):
            print(i)
            print(p1[6][i])
            print(p2[6][i])
            #self.assertEqual(p1[6][i], p2[6][i])
        self.assertEqual(p1[6], p2[6])
        for i in range(0,7):
            print(i)
            self.assertEqual(p1[i], p2[i])
        self.assertEqual(sorted(x.cubes_list), sorted(x_expected_cubes))
        #self.assertEqual(str(x), x_str_expected_new_3)
        '''

    def print_cubes_list(self, cubes):
        for c in cubes:
            cube_str = ','.join(str(x) for x in c)
            print(cube_str)

    @skip('active_dimensions is not supported')
    def test_eq(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        self.assertEqual(x, y)
        # print(x)
        # print(y)
        x.active_dimensions = ["ports", "methods_dfa"]
        y.active_dimensions = ["ports"]
        # print(x)
        # print(y)
        self.assertEqual(x, y)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_str_dfa("PUT")
        x.add_cube([ports_range, methods_dfa], ["ports", "methods_dfa"])
        y.add_cube([ports_range], ["ports"])
        # x.cubes_list.append([ports_range, methods_dfa])
        # y.cubes_list.append([ports_range])
        # print(x)
        # print(y)
        self.assertNotEqual(x, y)
        y.clear()
        y.active_dimensions = ["ports", "methods_dfa"]
        y.add_cube([ports_range, get_str_dfa("GET")], ["ports", "methods_dfa"])
        # y.cubes_list = [[ports_range, get_str_dfa("GET")]]
        # print(x)
        # print(y)
        self.assertNotEqual(x, y)
        y.clear()
        y.active_dimensions = ["ports", "methods_dfa"]
        y.add_cube([ports_range, get_str_dfa("PUT")], ["ports", "methods_dfa"])
        # y.cubes_list = [[ports_range, get_str_dfa("PUT")]]
        # print(x)
        # print(y)
        self.assertEqual(x, y)

    @skip('get_first_item is not supported.')
    def test_get_first_item(self):
        all = CanonicalHyperCubeSet(dimensions, True)
        item1 = all.get_first_item()
        item_str = ','.join(str(x) for x in item1)
        # print(item_str)
        self.assertTrue(item1 in all)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_str_dfa("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_dfa, paths_dfa]
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube(cube1, ["ports", "methods_dfa", "paths"])
        item2 = x.get_first_item()
        item_str = ','.join(str(x) for x in item2)
        # print(item_str)
        self.assertTrue(item2 in x)
        empty = CanonicalHyperCubeSet(dimensions)
        res_empty = empty.get_first_item()
        self.assertEqual(res_empty, NotImplemented)

    def test_cubes_with_empty_dimension(self):
        all = CanonicalHyperCubeSet(dimensions, True)
        hole1 = [CanonicalIntervalSet()]
        all.add_hole(hole1)
        self.assertEqual(all, CanonicalHyperCubeSet(dimensions, True))
        hole2 = [get_str_dfa("PUT") - get_str_dfa("PUT")]
        all.add_hole(hole2, ["methods_dfa"])
        self.assertEqual(all, CanonicalHyperCubeSet(dimensions, True))
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube([])
        # TODO: there is a bug in the original tests, the types of the dimensions
        #   is not correct, but this is not tested as the first cube is empty.
        #   This is the original line of code:
        # x.add_cube([CanonicalIntervalSet(), get_str_dfa("PUT")])
        #   and this is the fix:
        x.add_cube([CanonicalIntervalSet(), get_str_dfa("PUT")], ['src_ports', 'methods_dfa'])

        self.assertEqual(x, CanonicalHyperCubeSet(dimensions))
        # TODO: same as above
        # x.add_cube([CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("PUT") - get_str_dfa("PUT")])
        x.add_cube([CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("PUT") - get_str_dfa("PUT")],
                   ['src_ports', 'methods_dfa'])
        self.assertEqual(x, CanonicalHyperCubeSet(dimensions))
        # TODO: same as above
        # x.add_cube([CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("PUT")])
        x.add_cube([CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("PUT")],
                   ['src_ports', 'methods_dfa'])
        self.assertNotEqual(x, CanonicalHyperCubeSet(dimensions))

    @skip('__iter__ is not supported.')
    def test_iter(self):
        x = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(1, 10)],
                                                   ["ports"])
        y = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(100, 103)],
                                                   ["src_ports"])
        z = x | y
        for cube in iter(z):
            print(z.get_cube_str(cube))
        w = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("a*")], ["methods_dfa"])
        z |= w
        for cube in iter(z):
            print(z.get_cube_str(cube))
        print('---')
        w = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("b")], ["paths"])
        z |= w
        for cube in iter(z):
            print(z.get_cube_str(cube))
        all = CanonicalHyperCubeSet(dimensions, True)
        for cube in iter(all):
            print(','.join(str(x) for x in cube))

        w = CanonicalHyperCubeSet.create_from_cube(dimensions, [
            dim_manager.get_dimension_domain_by_name("methods_dfa") - get_str_dfa("a")], ["methods_dfa"])
        for cube in iter(w):
            print(w.get_cube_str(cube))

    def test_create_from_cube_new(self):
        x = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(1, 10),
                                                                CanonicalIntervalSet()], ["src_ports", "ports"])
        print(x)

    def test_contains(self):
        all = CanonicalHyperCubeSet(dimensions, True)
        empty = CanonicalHyperCubeSet(dimensions)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_str_dfa("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_dfa, paths_dfa]
        item1 = [15, 15, 'PUT', "abc"]
        item2 = [15, 150, 'PUT', "abc"]
        item3 = [150, 15, 'PUT', "abc"]
        item4 = [15, 15, 'PUT', "abcd"]
        self.assertTrue(item1 in all)
        self.assertFalse(item1 in empty)
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube(cube1, ["ports", "methods_dfa", "paths"])
        self.assertTrue(item1 in x)
        self.assertFalse(item2 in x)
        self.assertTrue(item3 in x)
        self.assertFalse(item4 in x)
        y = all.copy()
        y.add_hole([paths_dfa], ["paths"])
        self.assertFalse(item2 in y)
        self.assertTrue(item4 in y)
        z = CanonicalHyperCubeSet.create_from_cube(dimensions, [ports_range, ports_range, methods_dfa, paths_dfa],
                                                   dimensions)
        self.assertTrue(item1 in z)
        self.assertFalse(item4 in z)
        # test mismatch on input item
        try:
            res = [15] in y
            self.assertTrue(False)
        except Exception:
            self.assertTrue(True)

    def test_operators_basic(self):
        all = CanonicalHyperCubeSet(dimensions, True)
        empty = CanonicalHyperCubeSet(dimensions)
        x1 = empty.copy()
        x1.add_cube([get_str_dfa("abc")], ["methods_dfa"])
        res1 = all & x1
        self.assertEqual(res1, x1)
        res2 = x1 & all
        self.assertEqual(res2, x1)
        res3 = x1 & empty
        res4 = empty & x1
        self.assertEqual(res3, empty)
        self.assertEqual(res4, empty)

        res5 = all | x1
        self.assertEqual(res5, all)
        res6 = x1 | all
        self.assertEqual(res6, all)
        res7 = x1 | empty
        res8 = empty | x1
        self.assertEqual(res7, x1)
        self.assertEqual(res8, x1)

        res9 = x1 - empty
        res10 = x1 - all
        self.assertEqual(res9, x1)
        self.assertEqual(res10, empty)

        x1_copy = x1.copy()
        empty_hole = []
        x1.add_hole(empty_hole, [])
        self.assertEqual(x1, x1_copy)

        # skip this since we do not support _get_entire_space_cube
        # all_space_cube = x1._get_entire_space_cube()
        # x3 = x1.copy()
        # x3.add_cube(all_space_cube, dimensions)
        # self.assertEqual(x3, all)
        # x4 = x1.copy()
        # x4.add_hole(all_space_cube, dimensions)
        # self.assertEqual(x4, empty)
        # short_all_space_cube = [all_space_cube[2]]
        # x5 = x1.copy()
        # x5.add_cube(short_all_space_cube, ["methods_dfa"])
        # self.assertEqual(x5, all)

    def test_contained_in_2(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        p1 = CanonicalIntervalSet.get_interval_set(10, 20)
        p2 = CanonicalIntervalSet.get_interval_set(1, 5)
        p3 = CanonicalIntervalSet.get_interval_set(8, 200)
        x.add_cube([p1], ["ports"])
        y.add_cube([p2], ["ports"])
        y.add_cube([p3], ["ports"])
        self.assertTrue(x.contained_in(y))

    @skip('full regex is not supported.')
    def test_contained_in(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        ports_range_x = CanonicalIntervalSet.get_interval_set(10, 20)
        ports_range_y = CanonicalIntervalSet.get_interval_set(1, 200)
        x.add_cube([ports_range_x], ["ports"])
        y.add_cube([ports_range_y], ["ports"])
        res1 = x.contained_in(y)
        res2 = y.contained_in(x)
        self.assertTrue(res1)
        self.assertFalse(res2)
        # print(res1)
        # print(res2)

        x.clear()
        y.clear()
        paths_dfa_x = get_str_dfa("abc")
        paths_dfa_y = get_str_dfa("abc[\w]*")
        x.add_cube([paths_dfa_x], ["paths"])
        y.add_cube([paths_dfa_y], ["paths"])
        res1 = x.contained_in(y)
        res2 = y.contained_in(x)
        self.assertTrue(res1)
        self.assertFalse(res2)
        # print(res1)
        # print(res2)

        x.clear()
        y.clear()
        x.add_cube([paths_dfa_x], ["paths"])
        y.add_cube([ports_range_y], ["ports"])
        z = x & y
        # print(x)
        # print(y)
        res1 = x.contained_in(y)
        res2 = y.contained_in(x)
        res3 = z.contained_in(x)
        res4 = z.contained_in(y)
        # print(x)
        # print(y)
        # print(z)
        self.assertFalse(res1)
        self.assertFalse(res2)
        self.assertTrue(res3)
        self.assertTrue(res4)
        # print(res1)
        # print(res2)
        # print(res3)
        # print(res4)
        z.clear()  # is z "empty" or "all" ?
        # TODO: res5 should be true
        '''
        issues:
        1) when initializing a new object-> all active dimensions are empty
        2) when reducing unused dimensions( where all is allowed) -> arriving at empty active dimensions.
        possible solution: for an empty object, init with active dimensions as all dimensions.
        make sure to reduce dimensions for which all is allowed on following operations.
        -> allow all: (active_dimensions = [], cubes=[], layers = [])  [cube iteration returns the cube of all dimensions with all domains]
        -> allow nothing: (cubes = [], layers = [] , len(active_dimensions)>1 )  [cube iteraion returns nothing]
        '''

        # print(z)
        # print(x)
        res5 = x.contained_in(z)
        # print(res5)
        self.assertFalse(res5)
        z.set_all()
        res6 = x.contained_in(z)
        # print(res6)
        self.assertTrue(res6)

    @skip('regex not supported.')
    def test_contained_in_new(self):
        x = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("abc")], ["methods_dfa"])
        y = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(10, 20)],
                                                   ["ports"])
        self.assertFalse(x.contained_in(y))
        self.assertFalse(y.contained_in(x))
        z = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(10, 20)],
                                                   ["ports"])
        w = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(10, 20)],
                                                   ["ports"])
        w.add_cube([CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("abc")], ["ports", "methods_dfa"])
        print(z)
        print(w)
        self.assertTrue(z.contained_in(w))
        self.assertFalse(w.contained_in(z))
        w2 = CanonicalHyperCubeSet.create_from_cube(dimensions,
                                                    [CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("abc")],
                                                    ["ports", "methods_dfa"])
        self.assertFalse(z.contained_in(w2))
        w2.add_cube([CanonicalIntervalSet.get_interval_set(10, 20)], ["ports"])
        self.assertTrue(z.contained_in(w2))

        w2.add_cube([get_str_dfa("x")], ["methods_dfa"])
        z2 = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("x")], ["methods_dfa"])
        print(z2)
        print(w2)
        self.assertTrue(z2.contained_in(w2))
        w2.add_hole([CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("x")], ["ports", "methods_dfa"])
        self.assertFalse(z2.contained_in(w2))

        a = CanonicalHyperCubeSet.create_from_cube(dimensions,
                                                   [CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("x")],
                                                   ["ports", "methods_dfa"])
        b = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("x")], ["methods_dfa"])
        self.assertTrue(a.contained_in(b))

        c = CanonicalHyperCubeSet.create_from_cube(dimensions,
                                                   [CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("x")],
                                                   ["ports", "methods_dfa"])
        c.add_cube([CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("y")], ["ports", "methods_dfa"])
        d = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("x|y|z")], ["methods_dfa"])
        self.assertTrue(c.contained_in(d))

    @skip('_get_cubes_list_from_layers not supported.')
    def test_subtract_basic(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        x.add_cube([paths_dfa], ["paths"])
        y.add_cube([ports_range], ["ports"])
        z = y - x
        # print(x)
        # print(y)
        # print(z)
        z_cube_expected = [ports_range, dim_manager.get_dimension_domain_by_name("paths") - paths_dfa]
        self.assertEqual(z._get_cubes_list_from_layers(), [z_cube_expected])

    @skip('_get_cubes_set not supported.')
    def test_subtract_new(self):
        all = CanonicalHyperCubeSet(dimensions3, True)
        paths_dfa = get_str_dfa("abc")
        methods_dfa = get_str_dfa("PUT")
        hosts = dim_manager.get_dimension_domain_by_name("hosts")
        hole_cube = [methods_dfa, paths_dfa, hosts]
        all.add_hole(hole_cube, ["methods_dfa", "paths", "hosts"])
        # print(all)
        res_cube_1 = (methods_dfa, dim_manager.get_dimension_domain_by_name("paths") - paths_dfa)
        res_cube_2 = (dim_manager.get_dimension_domain_by_name("methods_dfa") - methods_dfa,
                      dim_manager.get_dimension_domain_by_name("paths"))
        expected_cubes = {res_cube_1, res_cube_2}
        self.assertEqual(expected_cubes, all._get_cubes_set())

    @skip('_get_cubes_set not supported.')
    def test_basic_or(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        x.add_cube([paths_dfa], ["paths"])
        y.add_cube([ports_range], ["ports"])
        # print(x)
        # print(y)
        z_cube_expected_1 = (
            CanonicalIntervalSet.get_interval_set(1, 9) | CanonicalIntervalSet.get_interval_set(21, 65535), paths_dfa)
        z_cube_expected_2 = (
            CanonicalIntervalSet.get_interval_set(10, 20), dim_manager.get_dimension_domain_by_name("paths"))
        z = x | y
        # print(z)
        self.assertEqual({z_cube_expected_1, z_cube_expected_2}, z._get_cubes_set())
        # print(z)

    @skip('_get_cubes_list_from_layers not supported.')
    def test_basic_and_2(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        x.add_cube([paths_dfa], ["paths"])
        y.add_cube([ports_range], ["ports"])
        # print(x)
        # print(y)
        z = x & y
        z_cube_expected = [ports_range, paths_dfa]
        self.assertEqual(z._get_cubes_list_from_layers(), [z_cube_expected])
        # print(z)

    @skip('_get_cubes_list_from_layers not supported.')
    def test_basic_and(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        ports_range1 = CanonicalIntervalSet.get_interval_set(15, 30)
        x.add_cube([ports_range, ports_range], ["src_ports", "ports"])
        y.add_cube([ports_range1, ports_range1], ["src_ports", "ports"])
        z = x & y
        res_cube = [CanonicalIntervalSet.get_interval_set(15, 20), CanonicalIntervalSet.get_interval_set(15, 20)]
        self.assertEqual(z._get_cubes_list_from_layers(), [res_cube])
        # print(z)

        x1 = CanonicalHyperCubeSet(dimensions)
        y1 = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        paths_dfa_new = get_str_dfa("abc|a")
        x1.add_cube([paths_dfa, paths_dfa], ["methods_dfa", "paths"])
        y1.add_cube([paths_dfa_new, paths_dfa_new], ["methods_dfa", "paths"])
        z1 = x1 & y1
        self.assertEqual(z1, x1)
        # print(z1)

        x2 = CanonicalHyperCubeSet(dimensions)
        y2 = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        paths_dfa_new = get_str_dfa("abc|a")
        x2.add_cube([paths_dfa], ["paths"])
        y2.add_cube([paths_dfa_new], ["paths"])
        z2 = x2 & y2
        self.assertEqual(z2, x2)
        # print(z2)

    @skip('_get_cubes_set not supported.')
    def test_add_hole_basic(self):
        x = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        paths_dfa_new = get_str_dfa("abc|a")
        methods_dfa_1 = get_str_dfa("x|m")
        methods_dfa_2 = get_str_dfa("y|m")
        paths_dfa2 = get_str_dfa("abcd")
        x.add_cube([methods_dfa_2, paths_dfa2], ["methods_dfa", "paths"])  # (y|m, abcd)
        res1 = {(get_str_dfa("y|m"), get_str_dfa("abcd"))}
        self.assertEqual(x._get_cubes_set(), res1)
        # print(x)
        x.add_cube([methods_dfa_1, paths_dfa_new], ["methods_dfa", "paths"])  # (x|m, abc)
        res2 = {(get_str_dfa("m"), get_str_dfa("a|abc|abcd")), (get_str_dfa("y"), get_str_dfa("abcd")),
                (get_str_dfa("x"), get_str_dfa("a|abc"))}
        self.assertEqual(x._get_cubes_set(), res2)
        # print(x)
        hole_dfa = get_str_dfa("m")
        x.add_hole([hole_dfa], ["methods_dfa"])
        res3 = {(get_str_dfa("y"), get_str_dfa("abcd")), (get_str_dfa("x"), get_str_dfa("a|abc"))}
        self.assertEqual(x._get_cubes_set(), res3)
        # print(x)
        hole_dfa = get_str_dfa("z")
        x.add_hole([hole_dfa], ["methods_dfa"])
        res4 = {(get_str_dfa("y"), get_str_dfa("abcd")), (get_str_dfa("x"), get_str_dfa("a|abc"))}
        # print(x)
        self.assertEqual(x._get_cubes_set(), res4)
        x.add_hole([methods_dfa_1, paths_dfa], ["methods_dfa", "paths"])
        # print(x)
        res5 = {(get_str_dfa("y"), get_str_dfa("abcd")), (get_str_dfa("x"), get_str_dfa("a"))}
        self.assertEqual(x._get_cubes_set(), res5)

    @skip('_get_cubes_set not supported.')
    def test_add_cube_dfa_basic_3(self):
        x = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        methods_dfa_1 = get_str_dfa("x")
        methods_dfa_2 = get_str_dfa("y")
        paths_dfa2 = get_str_dfa("abcd")
        paths_dfa3 = get_str_dfa("abcde")
        methods_dfa_3 = get_str_dfa("x|y|z")
        x.add_cube([paths_dfa], ["paths"])  # (*, abc)
        # print(x)
        res1 = {tuple([get_str_dfa("abc")])}
        self.assertEqual(x._get_cubes_set(), res1)
        x.add_cube([methods_dfa_2, paths_dfa2], ["methods_dfa", "paths"])  # (y, abcd)
        res2 = {(get_str_dfa("y"), get_str_dfa("abc|abcd")),
                (dim_manager.get_dimension_domain_by_name("methods_dfa") - get_str_dfa("y"), get_str_dfa("abc"))}
        self.assertEqual(x._get_cubes_set(), res2)
        # print(x)
        # TODO: test: update_layers_from_cubes_list  (sorting issue with MinDFA)

    @skip('_get_cubes_set not supported.')
    def test_add_cube_dfa_basic_2(self):
        x = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        methods_dfa_1 = get_str_dfa("x")
        methods_dfa_2 = get_str_dfa("y")
        paths_dfa2 = get_str_dfa("abcd")
        paths_dfa3 = get_str_dfa("abcde")
        methods_dfa_3 = get_str_dfa("x|y|z")

        x.add_cube([methods_dfa_1, paths_dfa], ["methods_dfa", "paths"])  # (x, abc)
        # print(x)
        res1 = {(get_str_dfa("x"), get_str_dfa("abc"))}
        self.assertEqual(x._get_cubes_set(), res1)
        x.add_cube([methods_dfa_2, paths_dfa2], ["methods_dfa", "paths"])  # (y, abcd)
        res2 = {(get_str_dfa("x"), get_str_dfa("abc")), (get_str_dfa("y"), get_str_dfa("abcd"))}
        self.assertEqual(x._get_cubes_set(), res2)
        # print(x)
        x.add_cube([methods_dfa_3, paths_dfa3], ["methods_dfa", "paths"])  # (x|y, abcde)
        res3 = {(get_str_dfa("x"), get_str_dfa("abc|abcde")), (get_str_dfa("y"), get_str_dfa("abcd|abcde")),
                (get_str_dfa("z"), get_str_dfa("abcde"))}
        # assert (x._get_cubes_set() == res3)
        # diff1 = x._get_cubes_set() -res3
        # diff2 = res3 - x._get_cubes_set()
        # print(f'diff1: {diff1}')
        # print(f'diff2: {diff2}')
        self.assertEqual(x._get_cubes_set(), res3)
        # print(x)

    @skip('_get_cubes_list_from_layers not supported.')
    def test_add_cube_dfa_basic(self):
        x = CanonicalHyperCubeSet(dimensions)
        paths_dfa = get_str_dfa("abc")
        x.add_cube([paths_dfa], ["paths"])
        res1 = [[get_str_dfa("abc")]]
        self.assertEqual(x._get_cubes_list_from_layers(), res1)
        # print(x)
        paths_dfa2 = get_str_dfa("a")
        x.add_cube([paths_dfa2], ["paths"])
        res2 = [[get_str_dfa("a|abc")]]
        self.assertEqual(x._get_cubes_list_from_layers(), res2)
        # print(x)
        y = x.copy()
        paths_dfa3 = get_str_dfa("a[bc]*")
        x.add_cube([paths_dfa3], ["paths"])
        res3 = [[get_str_dfa("a[bc]*")]]
        self.assertEqual(x._get_cubes_list_from_layers(), res3)
        self.assertEqual(y._get_cubes_list_from_layers(), res2)
        # print(x)
        # print(y)
        paths_dfa4 = get_str_dfa("a[b]*")
        y.add_cube([paths_dfa4], ["paths"])
        # print(y)
        res4 = [[get_str_dfa("a|abc|a[b]*")]]
        self.assertEqual(y._get_cubes_list_from_layers(), res4)

        '''
        methods_dfa = get_str_dfa("PUT")
        x.add_cube([methods_dfa], ["methods_dfa"])
        print(x)
        '''
        # print(x)

    @skip('_get_cubes_set not supported.')
    def test_basic_new(self):
        c = CanonicalHyperCubeSet(dimensions)
        c.add_cube([get_str_dfa("a"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        c.add_cube([get_str_dfa("p"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        c.add_cube([get_str_dfa("[p]*"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        d = CanonicalHyperCubeSet(dimensions)
        d.add_cube([get_str_dfa("pp"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        d.add_cube([get_str_dfa("[p]*"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        d.add_cube([get_str_dfa("a"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        self.assertEqual(c, d)
        a = CanonicalHyperCubeSet(dimensions)
        a.add_cube([CanonicalIntervalSet.get_interval_set(80, 80), get_str_dfa("abc")], ["ports", "paths"])
        a.add_cube([CanonicalIntervalSet.get_interval_set(80, 81), get_str_dfa("a")], ["ports", "paths"])
        res1 = {(CanonicalIntervalSet.get_interval_set(80, 80), get_str_dfa("a|abc")),
                (CanonicalIntervalSet.get_interval_set(81, 81), get_str_dfa("a"))}
        self.assertEqual(a._get_cubes_set(), res1)
        b = CanonicalHyperCubeSet(dimensions)
        b.add_cube([get_str_dfa("p"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        b.add_cube([get_str_dfa("[p]*"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        # print(b)
        res2 = {(get_str_dfa("p"), get_str_dfa("GET|PUT")),
                (get_str_dfa("[p]*") - get_str_dfa("p"), get_str_dfa("PUT"))}
        self.assertEqual(b._get_cubes_set(), res2)
        g = CanonicalHyperCubeSet(dimensions3)
        g.add_cube([get_str_dfa("a"), get_str_dfa("b"), get_str_dfa("c")], ["methods_dfa", "paths", "hosts"])
        g.add_cube([get_str_dfa("a"), get_str_dfa("e"), get_str_dfa("c")], ["methods_dfa", "paths", "hosts"])
        res3 = [[get_str_dfa("a"), get_str_dfa("b|e"), get_str_dfa("c")]]
        self.assertEqual(g._get_cubes_list_from_layers(), res3)
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube(
            [CanonicalIntervalSet.get_interval_set(80, 80), get_str_dfa("GET|PUT"), get_str_dfa("good1|good2|some2")],
            ["ports", "methods_dfa", "paths"])
        x.add_cube(
            [CanonicalIntervalSet.get_interval_set(90, 90), get_str_dfa("GET|PUT"), get_str_dfa("good1|good2|some2")],
            ["ports", "methods_dfa", "paths"])
        x.add_cube(
            [CanonicalIntervalSet.get_interval_set(1, 89), get_str_dfa("GET|HEAD"), get_str_dfa("bad1|bad3|some2")],
            ["ports", "methods_dfa", "paths"])
        x.add_cube([CanonicalIntervalSet.get_interval_set(91, 65535), get_str_dfa("GET|HEAD")],
                   ["ports", "methods_dfa"])
        x.add_hole(
            [CanonicalIntervalSet.get_interval_set(91, 65535), get_str_dfa("GET|HEAD"), get_str_dfa("bad1|bad3|some2")],
            ["ports", "methods_dfa", "paths"])
        # TODO: check cubes list more precisely
        # print(x)
        self.assertEqual(len(x), 6)
        a = CanonicalHyperCubeSet(dimensions, True)
        b = CanonicalHyperCubeSet(dimensions)
        b.add_cube([get_str_dfa("bad1")], ["methods_dfa"])
        a -= b
        self.assertEqual(a._get_cubes_list_from_layers(),
                         [[dim_manager.get_dimension_domain_by_name("methods_dfa") - get_str_dfa("bad1")]])
        a = CanonicalHyperCubeSet(dimensions)
        b = CanonicalHyperCubeSet(dimensions)
        c = CanonicalHyperCubeSet(dimensions)
        a.add_cube([get_str_dfa("a"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        self.assertEqual(a & a, a)
        b.add_cube([get_str_dfa("a"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        b.add_cube([get_str_dfa("b"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        self.assertEqual(a & b, a)
        self.assertNotEqual(a, b)
        c.add_cube([get_str_dfa("a|b"), get_str_dfa("PUT|GET")], ["methods_dfa", "paths"])
        self.assertEqual(a & c, a)
        self.assertEqual(b & c, b)
        a = CanonicalHyperCubeSet(dimensions)
        b = CanonicalHyperCubeSet(dimensions)
        a.add_cube([get_str_dfa("a"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        a.add_cube([get_str_dfa("b"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        b.add_cube([get_str_dfa("a|b"), get_str_dfa("PUT|GET")], ["methods_dfa", "paths"])
        self.assertTrue(a.contained_in(b))
        self.assertFalse(b.contained_in(a))
        a = CanonicalHyperCubeSet(dimensions)
        b = CanonicalHyperCubeSet(dimensions)
        c = CanonicalHyperCubeSet(dimensions)
        a.add_cube([get_str_dfa("a"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        a.add_cube([get_str_dfa("b"), get_str_dfa("PUT")], ["methods_dfa", "paths"])
        c.add_cube([get_str_dfa("a"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        c.add_cube([get_str_dfa("b"), get_str_dfa("GET")], ["methods_dfa", "paths"])
        b.add_cube([get_str_dfa("a|b"), get_str_dfa("PUT|GET")], ["methods_dfa", "paths"])
        self.assertEqual(a | c, b)
        empty = CanonicalHyperCubeSet(dimensions)
        self.assertEqual(a - a, empty)
        self.assertEqual(b - c, a)
        self.assertEqual(b - a, c)


class TestCanonicalHyperCubeSetMethodsIntervals(unittest.TestCase):
    """
    unit tests for CanonicalHyperCubeSet with interval-set dimensions (x,y,z).
    """

    def test_basic(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 2)], ["x"])
        a.add_cube([CanonicalIntervalSet.get_interval_set(5, 6)], ["x"])
        a.add_cube([CanonicalIntervalSet.get_interval_set(3, 4)], ["x"])
        res = CanonicalHyperCubeSet(dimensions4)
        res.add_cube([CanonicalIntervalSet.get_interval_set(1, 6)], ["x"])
        self.assertEqual(a, res)

    def test_basic_1(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(1, 5)],
                   ["x", "y"])
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(7, 9)],
                   ["x", "y"])
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(6, 7)],
                   ["x", "y"])
        res = CanonicalHyperCubeSet(dimensions4)
        res.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(1, 9)],
                     ["x", "y"])
        self.assertEqual(c, res)

    @skip('__hash__ is not supported.')
    def test_new(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(10, 20), CanonicalIntervalSet.get_interval_set(10, 20),
                    CanonicalIntervalSet.get_interval_set(1, 65535)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 65535), CanonicalIntervalSet.get_interval_set(15, 40),
                    CanonicalIntervalSet.get_interval_set(1, 65535)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 65535), CanonicalIntervalSet.get_interval_set(100, 200),
                    CanonicalIntervalSet.get_interval_set(30, 80)])
        res_cubes = set()
        res_cubes |= {(CanonicalIntervalSet.get_interval_set(1, 9) | CanonicalIntervalSet.get_interval_set(21, 65535),
                       CanonicalIntervalSet.get_interval_set(15, 40), CanonicalIntervalSet.get_interval_set(1, 65535))}
        res_cubes |= {(CanonicalIntervalSet.get_interval_set(1, 9) | CanonicalIntervalSet.get_interval_set(21, 65535),
                       CanonicalIntervalSet.get_interval_set(100, 200), CanonicalIntervalSet.get_interval_set(30, 80))}
        res_cubes |= {(CanonicalIntervalSet.get_interval_set(10, 20), CanonicalIntervalSet.get_interval_set(10, 40),
                       CanonicalIntervalSet.get_interval_set(1, 65535))}
        res_cubes |= {(CanonicalIntervalSet.get_interval_set(10, 20), CanonicalIntervalSet.get_interval_set(100, 200),
                       CanonicalIntervalSet.get_interval_set(30, 80))}
        # res_cubes |= {(CanonicalIntervalSet.get_interval_set(21, 65535), CanonicalIntervalSet.get_interval_set(15, 40), CanonicalIntervalSet.get_interval_set(1, 65535))}
        # res_cubes |= {(CanonicalIntervalSet.get_interval_set(21, 65535), CanonicalIntervalSet.get_interval_set(100, 200), CanonicalIntervalSet.get_interval_set(30, 80))}
        # print(c)
        self.assertEqual(c._get_cubes_set(), res_cubes)

    def test_eq(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        self.assertEqual(a, b)
        c = CanonicalHyperCubeSet(dimensions4)
        d = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(1, 5)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(1, 5)])
        self.assertEqual(c, d)
        # print(f'a: {a}')
        # print(f'c: {c}')
        # print(f'a cubes list: {a.cubes_list}')
        # a.print_cubes()
        # print(f'c cubes list: {c.cubes_list}')
        # c.print_cubes()

        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(7, 9)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(6, 7)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(4, 8), CanonicalIntervalSet.get_interval_set(1, 9)])
        res = CanonicalHyperCubeSet(dimensions4)
        res.add_cube([CanonicalIntervalSet.get_interval_set(4, 8), CanonicalIntervalSet.get_interval_set(1, 9)])
        res.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(1, 9)])
        self.assertEqual(res, c)
        # print(c)
        # c.print_cubes()
        a.add_cube([CanonicalIntervalSet.get_interval_set(5, 6)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(3, 4)])
        res1 = CanonicalHyperCubeSet(dimensions4)
        res1.add_cube([CanonicalIntervalSet.get_interval_set(1, 6)])
        self.assertEqual(res1, a)

        # a.print_cubes()
        d.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(1, 5)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(5, 6), CanonicalIntervalSet.get_interval_set(1, 5)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(3, 4), CanonicalIntervalSet.get_interval_set(1, 5)])
        res2 = CanonicalHyperCubeSet(dimensions4)
        res2.add_cube([CanonicalIntervalSet.get_interval_set(1, 6), CanonicalIntervalSet.get_interval_set(1, 5)])
        self.assertEqual(res2, d)
        # d.print_cubes()
        # print(d)
        # print('done')

    @skip('equality with string literal not supported.')
    def test_eq_2(self):
        a = CanonicalHyperCubeSet(dimensions4)
        b = CanonicalHyperCubeSet(dimensions4)  # TODO: change dimensions4
        c = "string"
        self.assertNotEqual(a, c)

    def test_basic_new_add_cube(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(8, 10)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(6, 10)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 10)])
        res = CanonicalHyperCubeSet(dimensions4)
        res.add_cube([CanonicalIntervalSet.get_interval_set(1, 10)])
        self.assertEqual(a, res)

    def test_add_hole_basic(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 10)])
        b = a.copy()
        c = a.copy()
        d = a.copy()
        e = a.copy()
        a.add_hole([CanonicalIntervalSet.get_interval_set(3, 7)])
        b.add_hole([CanonicalIntervalSet.get_interval_set(3, 20)])
        c.add_hole([CanonicalIntervalSet.get_interval_set(0, 20)])
        d.add_hole([CanonicalIntervalSet.get_interval_set(0, 5)])
        e.add_hole([CanonicalIntervalSet.get_interval_set(12, 14)])
        res = []
        for _ in range(0, 5):
            res.append(CanonicalHyperCubeSet(dimensions4))
        res[0].add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        res[0].add_cube([CanonicalIntervalSet.get_interval_set(8, 10)])
        res[1].add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        res[3].add_cube([CanonicalIntervalSet.get_interval_set(6, 10)])
        res[4].add_cube([CanonicalIntervalSet.get_interval_set(1, 10)])
        self.assertEqual(a, res[0])
        self.assertEqual(b, res[1])
        self.assertEqual(c, res[2])
        self.assertEqual(d, res[3])
        self.assertEqual(e, res[4])

    def test_add_hole_basic_2(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        b = a.copy()
        c = a.copy()
        d = a.copy()
        e = a.copy()
        a.add_hole([CanonicalIntervalSet.get_interval_set(50, 60), CanonicalIntervalSet.get_interval_set(220, 300)])
        res_a = CanonicalHyperCubeSet(dimensions4)
        res_a.add_cube(
            [CanonicalIntervalSet.get_interval_set(61, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        res_a.add_cube([CanonicalIntervalSet.get_interval_set(50, 60), CanonicalIntervalSet.get_interval_set(200, 219)])
        res_a.add_cube([CanonicalIntervalSet.get_interval_set(1, 49), CanonicalIntervalSet.get_interval_set(200, 300)])
        self.assertEqual(a, res_a)
        # print(a)
        # a.print_cubes()
        # print(b)

        b.add_hole([CanonicalIntervalSet.get_interval_set(50, 1000), CanonicalIntervalSet.get_interval_set(0, 250)])
        res_b = CanonicalHyperCubeSet(dimensions4)
        res_b.add_cube(
            [CanonicalIntervalSet.get_interval_set(50, 100), CanonicalIntervalSet.get_interval_set(251, 300)])
        res_b.add_cube([CanonicalIntervalSet.get_interval_set(1, 49), CanonicalIntervalSet.get_interval_set(200, 300)])
        self.assertEqual(b, res_b)
        # print(b)
        # b.print_cubes()

        c.add_cube([CanonicalIntervalSet.get_interval_set(400, 700), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_hole([CanonicalIntervalSet.get_interval_set(50, 1000), CanonicalIntervalSet.get_interval_set(0, 250)])
        res_c = CanonicalHyperCubeSet(dimensions4)
        res_c.add_cube(
            [CanonicalIntervalSet.get_interval_set(50, 100), CanonicalIntervalSet.get_interval_set(251, 300)])
        res_c.add_cube([CanonicalIntervalSet.get_interval_set(1, 49), CanonicalIntervalSet.get_interval_set(200, 300)])
        res_c.add_cube(
            [CanonicalIntervalSet.get_interval_set(400, 700), CanonicalIntervalSet.get_interval_set(251, 300)])
        self.assertEqual(c, res_c)
        # print(c)
        # c.print_cubes()

    def test_add_hole(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_hole([CanonicalIntervalSet.get_interval_set(50, 60), CanonicalIntervalSet.get_interval_set(220, 300)])
        d = CanonicalHyperCubeSet(dimensions4)
        d.add_cube([CanonicalIntervalSet.get_interval_set(1, 49), CanonicalIntervalSet.get_interval_set(200, 300)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(50, 60), CanonicalIntervalSet.get_interval_set(200, 219)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(61, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        # print('c:')
        # c.print_cubes()
        # print('d:')
        # d.print_cubes()
        self.assertEqual(c, d)

    def test_add_hole_2(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(80, 100), CanonicalIntervalSet.get_interval_set(20, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(250, 400), CanonicalIntervalSet.get_interval_set(20, 300)])
        c.add_hole([CanonicalIntervalSet.get_interval_set(30, 300), CanonicalIntervalSet.get_interval_set(100, 102)])
        d = CanonicalHyperCubeSet(dimensions4)
        d.add_cube([CanonicalIntervalSet.get_interval_set(80, 100), CanonicalIntervalSet.get_interval_set(20, 99)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(80, 100), CanonicalIntervalSet.get_interval_set(103, 300)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(250, 300), CanonicalIntervalSet.get_interval_set(20, 99)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(250, 300), CanonicalIntervalSet.get_interval_set(103, 300)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(301, 400), CanonicalIntervalSet.get_interval_set(20, 300)])
        self.assertEqual(c, d)

    def test_add_hole_3(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_hole([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        d = CanonicalHyperCubeSet(dimensions4)
        self.assertEqual(c, d)

    def test_apply_intervals_union(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(101, 200), CanonicalIntervalSet.get_interval_set(200, 300)])
        d = CanonicalHyperCubeSet(dimensions4)
        d.add_cube([CanonicalIntervalSet.get_interval_set(1, 200), CanonicalIntervalSet.get_interval_set(200, 300)])
        self.assertEqual(c, d)
        # TODO: we do not support canonical string representation.
        # self.assertEqual(str(c), str(d))

    def test_apply_intervals_union_2(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(101, 200), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(201, 300), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(301, 400), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(402, 500), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(500, 600), CanonicalIntervalSet.get_interval_set(200, 700)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(601, 700), CanonicalIntervalSet.get_interval_set(200, 700)])

        d = c.copy()
        d.add_cube([CanonicalIntervalSet.get_interval_set(702, 800), CanonicalIntervalSet.get_interval_set(200, 700)])
        c_expected = CanonicalHyperCubeSet(dimensions4)
        c_expected.add_cube(
            [CanonicalIntervalSet.get_interval_set(1, 400), CanonicalIntervalSet.get_interval_set(200, 300)])
        c_expected.add_cube(
            [CanonicalIntervalSet.get_interval_set(402, 500), CanonicalIntervalSet.get_interval_set(200, 300)])
        c_expected.add_cube(
            [CanonicalIntervalSet.get_interval_set(500, 700), CanonicalIntervalSet.get_interval_set(200, 700)])
        d_expected = c_expected.copy()
        d_expected.add_cube(
            [CanonicalIntervalSet.get_interval_set(702, 800), CanonicalIntervalSet.get_interval_set(200, 700)])
        self.assertEqual(c, c_expected)
        self.assertEqual(d, d_expected)

    def test_contains(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 2), CanonicalIntervalSet.get_interval_set(1, 5)])
        item = [1, 3, 1]
        self.assertTrue(item in c)
        item = [1, 10, 1]
        self.assertFalse(item in c)
        item = [10, 10, 1]
        self.assertFalse(item in c)
        d = CanonicalHyperCubeSet(dimensions4)
        d.add_cube([CanonicalIntervalSet.get_interval_set(1, 10)])
        self.assertTrue([3, 1, 1] in d)
        self.assertFalse([0, 1, 1] in d)
        self.assertFalse([12, 1, 1] in d)

    # TODO: extend this test
    def test_and_sub_or(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(5, 15), CanonicalIntervalSet.get_interval_set(3, 10)])
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube([CanonicalIntervalSet.get_interval_set(8, 30), CanonicalIntervalSet.get_interval_set(7, 20)])
        c = a & b
        d = CanonicalHyperCubeSet(dimensions4)
        d.add_cube([CanonicalIntervalSet.get_interval_set(8, 15), CanonicalIntervalSet.get_interval_set(7, 10)])
        self.assertEqual(c, d)
        # print(c)
        # c.print_cubes()
        # print(d)
        # d.print_cubes()

        f = a | b
        e = CanonicalHyperCubeSet(dimensions4)
        e.add_cube([CanonicalIntervalSet.get_interval_set(5, 15), CanonicalIntervalSet.get_interval_set(3, 6)])
        e.add_cube([CanonicalIntervalSet.get_interval_set(5, 30), CanonicalIntervalSet.get_interval_set(7, 10)])
        e.add_cube([CanonicalIntervalSet.get_interval_set(8, 30), CanonicalIntervalSet.get_interval_set(11, 20)])
        self.assertEqual(e, f)
        # print(f)
        # print(e)
        g = a - b
        h = CanonicalHyperCubeSet(dimensions4)
        h.add_cube([CanonicalIntervalSet.get_interval_set(5, 7), CanonicalIntervalSet.get_interval_set(3, 10)])
        h.add_cube([CanonicalIntervalSet.get_interval_set(8, 15), CanonicalIntervalSet.get_interval_set(3, 6)])
        # print(g)
        # print(h)
        self.assertEqual(g, h)

    def test_and_2(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(5, 15), CanonicalIntervalSet.get_interval_set(3, 10)])
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube([CanonicalIntervalSet.get_interval_set(1, 3), CanonicalIntervalSet.get_interval_set(7, 20)])
        b.add_cube([CanonicalIntervalSet.get_interval_set(20, 23), CanonicalIntervalSet.get_interval_set(7, 20)])
        c = a & b
        d = CanonicalHyperCubeSet(dimensions4)
        self.assertEqual(c, d)

    def test_or_2(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube(
            [CanonicalIntervalSet.get_interval_set(80, 100), CanonicalIntervalSet.get_interval_set(10053, 10053)])
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube(
            [CanonicalIntervalSet.get_interval_set(1, 65535), CanonicalIntervalSet.get_interval_set(10054, 10054)])
        a |= b
        expected_res = CanonicalHyperCubeSet(dimensions4)
        expected_res.add_cube(
            [CanonicalIntervalSet.get_interval_set(1, 79), CanonicalIntervalSet.get_interval_set(10054, 10054)])
        expected_res.add_cube(
            [CanonicalIntervalSet.get_interval_set(80, 100), CanonicalIntervalSet.get_interval_set(10053, 10054)])
        expected_res.add_cube([CanonicalIntervalSet.get_interval_set(101, 65535),
                               CanonicalIntervalSet.get_interval_set(10054, 10054)])
        self.assertEqual(a, expected_res)

    def test_contained_in(self):
        c = CanonicalHyperCubeSet(dimensions4)
        d = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(10, 80), CanonicalIntervalSet.get_interval_set(210, 280)])
        self.assertTrue(d.contained_in(c))
        d.add_cube([CanonicalIntervalSet.get_interval_set(10, 200), CanonicalIntervalSet.get_interval_set(210, 280)])
        self.assertFalse(d.contained_in(c))

    def test_contained_in_2(self):
        a = CanonicalHyperCubeSet(dimensions4)
        c = CanonicalHyperCubeSet(dimensions4)
        d = CanonicalHyperCubeSet(dimensions4)
        e = CanonicalHyperCubeSet(dimensions4)
        f = CanonicalHyperCubeSet(dimensions4)
        f1 = CanonicalHyperCubeSet(dimensions4)
        f2 = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(150, 180), CanonicalIntervalSet.get_interval_set(20, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(200, 240), CanonicalIntervalSet.get_interval_set(200, 300)])
        c.add_cube([CanonicalIntervalSet.get_interval_set(241, 300), CanonicalIntervalSet.get_interval_set(200, 350)])

        a.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(150, 180), CanonicalIntervalSet.get_interval_set(20, 300)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(200, 240), CanonicalIntervalSet.get_interval_set(200, 300)])
        a.add_cube([CanonicalIntervalSet.get_interval_set(242, 300), CanonicalIntervalSet.get_interval_set(200, 350)])

        d.add_cube([CanonicalIntervalSet.get_interval_set(210, 220), CanonicalIntervalSet.get_interval_set(210, 280)])
        e.add_cube([CanonicalIntervalSet.get_interval_set(210, 310), CanonicalIntervalSet.get_interval_set(210, 280)])
        f.add_cube([CanonicalIntervalSet.get_interval_set(210, 250), CanonicalIntervalSet.get_interval_set(210, 280)])
        f1.add_cube([CanonicalIntervalSet.get_interval_set(210, 240), CanonicalIntervalSet.get_interval_set(210, 280)])
        f2.add_cube([CanonicalIntervalSet.get_interval_set(241, 250), CanonicalIntervalSet.get_interval_set(210, 280)])

        self.assertTrue(d.contained_in(c))
        self.assertFalse(e.contained_in(c))
        self.assertTrue(f1.contained_in(c))
        self.assertTrue(f2.contained_in(c))
        self.assertTrue(f.contained_in(c))
        self.assertFalse(f.contained_in(a))

    def test_contained_in_3(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(105, 105), CanonicalIntervalSet.get_interval_set(54, 54)])
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube([CanonicalIntervalSet.get_interval_set(0, 204), CanonicalIntervalSet.get_interval_set(0, 255)])
        b.add_cube([CanonicalIntervalSet.get_interval_set(205, 205), CanonicalIntervalSet.get_interval_set(0, 53)])
        b.add_cube([CanonicalIntervalSet.get_interval_set(205, 205), CanonicalIntervalSet.get_interval_set(55, 255)])
        b.add_cube([CanonicalIntervalSet.get_interval_set(206, 254), CanonicalIntervalSet.get_interval_set(0, 255)])
        res = a.contained_in(b)
        self.assertTrue(res)

    def test_contained_in_4(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(105, 105), CanonicalIntervalSet.get_interval_set(54, 54)])
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube([CanonicalIntervalSet.get_interval_set(200, 204), CanonicalIntervalSet.get_interval_set(0, 255)])
        self.assertFalse(a.contained_in(b))

    def test_contained_in_5(self):
        a = CanonicalHyperCubeSet(dimensions4)
        a.add_cube([CanonicalIntervalSet.get_interval_set(100, 200), CanonicalIntervalSet.get_interval_set(54, 65),
                    CanonicalIntervalSet.get_interval_set(60, 300)])
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube([CanonicalIntervalSet.get_interval_set(110, 120), CanonicalIntervalSet.get_interval_set(0, 10),
                    CanonicalIntervalSet.get_interval_set(0, 255)])
        self.assertFalse(b.contained_in(a))

    def test_bool(self):
        a = CanonicalHyperCubeSet(dimensions4)
        self.assertFalse(bool(a))
        b = CanonicalHyperCubeSet(dimensions4)
        b.add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        self.assertTrue(bool(b))
        c = CanonicalHyperCubeSet(dimensions4)
        self.assertFalse(bool(c))
        d = CanonicalHyperCubeSet(dimensions4)
        d.add_cube([CanonicalIntervalSet.get_interval_set(10, 200), CanonicalIntervalSet.get_interval_set(210, 280)])
        self.assertTrue(bool(d))

    def test_copy(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        d = c.copy()
        self.assertEqual(c, d)

    @skip('__len__ not supported.')
    def test_len(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        self.assertEqual(len(c), 1)
        d = CanonicalHyperCubeSet(dimensions4)
        d.add_cube([CanonicalIntervalSet.get_interval_set(1, 2)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(4, 5)])
        d.add_cube([CanonicalIntervalSet.get_interval_set(7, 9)])
        self.assertEqual(len(d), 1)
        c.add_cube([CanonicalIntervalSet.get_interval_set(200, 300), CanonicalIntervalSet.get_interval_set(200, 300)])
        self.assertEqual(len(c), 1)

    @skip('get_first_item not supported.')
    def test_get_first_item(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        res = c.get_first_item()
        expected = [1, 200, 1]
        self.assertEqual(res, expected)
        d = CanonicalHyperCubeSet(dimensions4)
        res = d.get_first_item()
        self.assertTrue(res is NotImplemented)

    def test_clear(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        d = CanonicalHyperCubeSet(dimensions4)
        c.clear()
        self.assertEqual(c, d)

    @skip('__hash__ not supported.')
    def test_hash(self):
        x = dict()
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        d = c.copy()
        e = CanonicalHyperCubeSet(dimensions4)
        x[c] = 'c'
        x[e] = 'e'
        self.assertEqual(x[c], x[d])
        self.assertNotEqual(x[c], x[e])

    @skip('__str__ not supported.')
    def test_str(self):
        c = CanonicalHyperCubeSet(dimensions4)
        self.assertEqual(str(c), "Empty")
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        print(c)
        self.assertEqual(str(c), "x,y: (1-100, 200-300, )")
        # self.assertEqual(str(c), "x,y: ([1-100], [200-300], )")
        # self.assertEqual(str(c), "[1-100] => [[200-300]];")

    def test_hole_new(self):
        c = CanonicalHyperCubeSet(dimensions4)
        c.add_cube([CanonicalIntervalSet.get_interval_set(1, 100), CanonicalIntervalSet.get_interval_set(200, 300)])
        x = [CanonicalIntervalSet.get_interval_set(50, 50)]
        c.add_hole(x)  # added hole is [50, all]
        print(c)
        y = [CanonicalIntervalSet.get_interval_set(250, 250)]
        c.add_hole(y, ["y"])  # added hole is [all, 250]
        print(c)
        hole_new = [CanonicalIntervalSet.get_interval_set(70, 70), CanonicalIntervalSet.get_interval_set(280, 280)]
        c.add_hole(hole_new)
        print(c)

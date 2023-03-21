import unittest
from nca.CoreDS.MethodSet import MethodSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.MinDFA import MinDFA
from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.DimensionsManager import DimensionsManager

dimensions = ["src_ports", "ports", "methods", "paths"]
dimensions2 = ["ports", "src_ports", "methods", "paths"]
dimensions3 = ["src_ports", "ports", "methods", "paths", "hosts"]
dim_manager = DimensionsManager()
dim_manager.set_domain("ports", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
# overriding domain of paths dimension to be [\w]* instead of /[\w]*
# currently the tests assume a path value does not have to start with '/'.
# when using the domain /[\w]* with current tests, some will fail.
# some detailed explanation at commented out test test_basic_or_2
dim_manager.set_domain("paths", DimensionsManager.DimensionType.DFA)


def get_str_dfa(s):
    return MinDFA.dfa_from_regex(s)


def get_method_interval(m):
    res = MethodSet()
    index = MethodSet.all_methods_list.index(m)
    res.add_interval(MethodSet.Interval(index, index))
    return res


class TestCanonicalHyperCubeSetMethodsNew(unittest.TestCase):
    """
    unit tests for CanonicalHyperCubeSet with methods dimension of type IntervalSet.
    """

    def test_dfa_equality(self):
        dfa_all = dim_manager.get_dimension_domain_by_name("paths")
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

    def test_create_from_cube(self):
        s = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_method_interval("PUT")], ["methods"])
        print(s)
        ports_range = CanonicalIntervalSet.get_interval_set(100, 200)
        methods_interval = get_method_interval("PUT")
        cube2 = [ports_range, methods_interval]
        x = CanonicalHyperCubeSet.create_from_cube(dimensions, cube2, ["ports", "methods"])
        print(x)

    def test_set_active_dims_new(self):
        x = CanonicalHyperCubeSet(dimensions3)
        x.add_cube([get_method_interval("PUT")], ["methods"])
        print(x)
        x.build_new_active_dimensions(["ports", "methods", "paths", "hosts"])
        print(x)

    def test_remove_active_dims_new(self):
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube([get_method_interval("PUT")], ["methods"])
        x.build_new_active_dimensions(["ports", "methods", "paths", "hosts"])
        y = x.copy()
        z = x.copy()
        print(x)
        x._remove_some_active_dimensions(["methods", "paths", "hosts"])
        y._remove_some_active_dimensions(["methods"])
        z._remove_some_active_dimensions(["ports", "methods"])
        print(x)
        print(y)
        print(z)

    def test_set_active_dimensions(self):
        x = CanonicalHyperCubeSet.create_from_cube(dimensions3, [get_method_interval("PUT"), get_str_dfa("abc")],
                                                   ["methods", "paths"])
        print(x)
        x._set_active_dimensions({"methods"})
        print(x)
        x._set_active_dimensions({"methods", "paths"})
        print(x)
        x._set_active_dimensions({"methods", "paths", "hosts"})
        print(x)
        x._set_active_dimensions({"methods", "paths", "hosts", "ports"})
        print(x)

    '''
    def test_basic(self):
        x = CanonicalHyperCubeSet(dimensions)
        a1 = CanonicalIntervalSet.get_interval_set(1, 20)
        x.add_cube([a1, a1], ["src_ports", "ports"])
        print(x)
        a2 = CanonicalIntervalSet.get_interval_set(15, 40)
        x.add_cube([a2], ["ports"])
        print(x)
        a3 = CanonicalIntervalSet.get_interval_set(100, 200)
        x.add_cube([a3, get_str_dfa("PUT")], ["ports", "methods"])
        print(x)

    def test_basic_new_1(self):
        x = CanonicalHyperCubeSet(dimensions)
        a1 = CanonicalIntervalSet.get_interval_set(1, 20)
        a2 = CanonicalIntervalSet.get_interval_set(100, 200)
        x.add_cube([a1, a1])
        x.add_cube([a2, a2])
        x.add_cube([a1, a2])
        x.add_cube([a2, a1])
        print(x)
        x_str = str(x)
    '''

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

        new_active_dimensions = ["ports", "methods"]
        ports_range = CanonicalIntervalSet.get_interval_set(1, 20)
        methods_intervals = get_method_interval("GET")
        cube = [ports_range, methods_intervals]
        x.add_cube(cube, new_active_dimensions)
        self.assertEqual(x._get_cubes_list_from_layers(), [cube])

        ports_range = CanonicalIntervalSet.get_interval_set(100, 200)
        methods_intervals = get_method_interval("PUT")
        cube2 = [ports_range, methods_intervals]
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
        methods_intervals = get_method_interval("GET")
        cube = [ports_range, methods_intervals]
        x.add_cube(cube, ["ports", "methods"])  # is now equals this cube
        y.add_cube(cube, ["ports", "methods"])  # y remains all
        self.assertNotEqual(x, y)

        z = CanonicalHyperCubeSet(dimensions, True)
        z.add_hole(cube, ["ports", "methods"])  # z should be the complement of x
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

    '''
    def test_cubes_count_new(self):
        dim_types = ["Interval"]*20
        print(dim_types)
        chars = list(string.ascii_lowercase)
        dim_names = chars[0:20]
        print(dim_names)
        print(len(dim_names))
        print(len(dim_types))
        interval_domain = (1,100000)
        dim_domains = [interval_domain]*20
        print(dim_domains)
        interval_domain_object = CanonicalIntervalSet.get_interval_set(1, 100000)
        dim_domains_values = dict()
        for n in dim_names:
            dim_domains_values[n] =interval_domain_object
        dimensions_new = Dimensions(dim_types, dim_names, dim_domains, dim_domains_values)

        x = CanonicalHyperCubeSet(dimensions_new)
        a1 = CanonicalIntervalSet.get_interval_set(1, 20)
        x.add_cube([a1, a1], ["a", "b"])
        print(x)
        print(len(x))
        a2 = CanonicalIntervalSet.get_interval_set(15, 40)
        x.add_cube([a2], ["b"])
        print(x)
        print(len(x))
        cube = [CanonicalIntervalSet.get_interval_set(100, 200), CanonicalIntervalSet.get_interval_set(300, 400)]
        #print(str(cube[0]), str(cube[1]))
        for i in range(1, 18):
            cube_dims = [dim_names[i], dim_names[i+1]]
            x.add_cube(cube, cube_dims)
            if i<=3:
                print(x)
            #print(cube_dims)
            w= next(iter(cube[0]))
            y = next(iter(cube[1]))
            w.start+= 200
            w.end += 200
            y.start+= 200
            y.end += 200
            cube = [CanonicalIntervalSet.get_interval_set(w.start, w.end), CanonicalIntervalSet.get_interval_set(y.start, y.end)]
            #cube = [w, y]
            #print(str(cube[0]), str(cube[1]))
            print(f'i: {i}, x_len: {len(x)}')
    '''

    def test_basic_3(self):
        """
        test basic case for correctness of reduce_active_dimensions
        """
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        z = CanonicalHyperCubeSet(dimensions, True)
        paths_dfa1 = dim_manager.get_dimension_domain_by_name("paths") - get_str_dfa("a")
        paths_dfa2 = get_str_dfa("a")
        x.add_cube([paths_dfa1], ["paths"])
        y.add_cube([paths_dfa2], ["paths"])
        w = x | y
        self.assertEqual(x.active_dimensions, ["paths"])
        self.assertEqual(y.active_dimensions, ["paths"])
        self.assertEqual(w.active_dimensions, [])
        self.assertEqual(z.active_dimensions, [])
        self.assertEqual(w, z)

    def test_eq_basic(self):
        x = CanonicalHyperCubeSet(dimensions)
        self.assertNotEqual("s", x)
        # TODO: test Dimensions __eq__ ?
        y = CanonicalHyperCubeSet(dimensions2)
        self.assertNotEqual(y, x)

    def test_len_basic(self):
        all = CanonicalHyperCubeSet(dimensions3, True)
        empty = CanonicalHyperCubeSet(dimensions3)
        x1 = empty.copy()
        x1.add_cube([get_str_dfa("a")], ["paths"])
        x2 = empty.copy()
        x2.add_cube([get_str_dfa("b")], ["hosts"])
        x2.add_cube([get_str_dfa("a")], ["paths"])
        # print(x1)
        # print(x2)
        self.assertEqual(len(all), 1)
        self.assertEqual(len(empty), 0)
        self.assertEqual(len(x1), 1)
        self.assertEqual(len(x2), 2)

    def test_hash_basic(self):
        d = dict()
        all1 = CanonicalHyperCubeSet(dimensions, True)
        empty1 = CanonicalHyperCubeSet(dimensions)
        x1 = empty1.copy()
        x1.add_cube([get_str_dfa("a")], ["paths"])
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
        methods_intervals = get_method_interval("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_intervals]
        ports_rang2 = CanonicalIntervalSet.get_interval_set(100, 200)
        cube2 = [ports_rang2, methods_intervals, paths_dfa]
        x.add_cube(cube1, ["ports", "methods"])
        # print(x)
        y = x.copy()
        x.add_hole(cube2, ["ports", "methods", "paths"])
        # print(x)
        # print(y)
        self.assertEqual(x, y)

    def test_reduce_active_dimensions_2(self):
        x = CanonicalHyperCubeSet(dimensions)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_intervals = get_method_interval("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_intervals]
        ports_rang2 = CanonicalIntervalSet.get_interval_set(100, 200)
        cube2 = [ports_rang2, methods_intervals, paths_dfa]
        cube3 = [CanonicalIntervalSet.get_interval_set(500, 600)]
        x.add_cube(cube1, ["ports", "methods"])
        x.add_cube(cube3, ["ports"])
        y = CanonicalHyperCubeSet(dimensions)
        y.add_cube(cube2, ["ports", "methods", "paths"])
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

    def test_canonical_rep_dfa_new(self):
        dfa1 = get_str_dfa("[ab]*")
        dfa2 = get_str_dfa("[bc]*")
        dfa3 = get_str_dfa("[ac]*")
        dfa4 = get_str_dfa("a")
        dfa5 = get_str_dfa("b")
        dfa6 = get_str_dfa("c")

        x = CanonicalHyperCubeSet(dimensions3)
        y = CanonicalHyperCubeSet(dimensions3)

        x.add_cube([dfa1, dfa4], ["paths", "hosts"])
        # print(f'x1: {x}')
        x.add_cube([dfa2, dfa5], ["paths", "hosts"])
        # print(f'x2: {x}')
        x.add_cube([dfa3, dfa6], ["paths", "hosts"])
        # print(f'x3: {x}')
        # print(x)

        y.add_cube([dfa2, dfa5], ["paths", "hosts"])
        # print(f'y1: {y}')
        y.add_cube([dfa3, dfa6], ["paths", "hosts"])
        # print(f'y2: {y}')
        y.add_cube([dfa1, dfa4], ["paths", "hosts"])
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

        x = CanonicalHyperCubeSet(dimensions3)
        y = CanonicalHyperCubeSet(dimensions3)

        x.add_cube([dfa1, dfa4], ["paths", "hosts"])
        # print(f'x1: {x}')
        x.add_cube([dfa2, dfa5], ["paths", "hosts"])
        # print(f'x2: {x}')
        x.add_cube([dfa3, dfa6], ["paths", "hosts"])
        # print(f'x3: {x}')
        # print(x)

        y.add_cube([dfa2, dfa5], ["paths", "hosts"])
        # print(f'y1: {y}')
        y.add_cube([dfa3, dfa6], ["paths", "hosts"])
        # print(f'y2: {y}')
        y.add_cube([dfa1, dfa4], ["paths", "hosts"])
        # print(f'y3: {y}')
        # print(y)
        self.assertEqual(x, y)

    def test_canonical_rep_dfa_new_2(self):
        dfa1 = get_str_dfa("a[a]+")
        dfa1_s = get_str_dfa("b")
        dfa2 = get_str_dfa("b[b]+")
        dfa2_s = get_str_dfa("c")
        dfa3 = get_str_dfa("a|b")
        dfa3_s = get_str_dfa("b|c")
        x = CanonicalHyperCubeSet(dimensions3)
        x.add_cube([dfa1, dfa1_s], ["paths", "hosts"])
        x.add_cube([dfa2, dfa2_s], ["paths", "hosts"])
        x.add_cube([dfa3, dfa3_s], ["paths", "hosts"])
        # print(x)

        dfa4 = get_str_dfa("[a]+|b")
        dfa4_s = get_str_dfa("b")
        dfa5 = get_str_dfa("[b]+|a")
        dfa5_s = get_str_dfa("c")
        y = CanonicalHyperCubeSet(dimensions3)
        y.add_cube([dfa4, dfa4_s], ["paths", "hosts"])
        y.add_cube([dfa5, dfa5_s], ["paths", "hosts"])
        # print(y)
        self.assertEqual(x, y)

    def test_empty_dfa_new(self):
        paths_dfa = get_str_dfa("[a]*")
        paths_dfa2 = get_str_dfa("[ab]*")
        m = CanonicalHyperCubeSet(dimensions)
        # n = CanonicalHyperCubeSet(dimensions)
        m.add_cube([paths_dfa], ["paths"])
        m.add_hole([paths_dfa2], ["paths"])
        self.assertEqual(m, CanonicalHyperCubeSet(dimensions))
        # print(m)

    def test_intersection(self):
        methods_intervals = get_method_interval("PUT")
        cube3 = [CanonicalIntervalSet.get_interval_set(500, 600)]
        m = CanonicalHyperCubeSet(dimensions)
        n = CanonicalHyperCubeSet(dimensions)
        cube4 = [methods_intervals]
        m.add_cube(cube4, ["methods"])
        n.add_cube(cube4, ["methods"])
        m.add_cube(cube3, ["ports"])
        # print(m)
        # print(n)
        k = m & n
        # print(k)
        self.assertEqual(k.active_dimensions, ["methods"])
        self.assertEqual(k, n)
        self.assertNotEqual(k, m)
        self.assertNotEqual(n, m)

    def test_add_cube_new(self):
        paths_dfa = get_str_dfa("abc")
        methods_intervals1 = get_method_interval("PUT")
        methods_intervals2 = get_method_interval("GET")
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube([methods_intervals1, paths_dfa], ["methods", "paths"])
        self.assertEqual(1, len(x))
        x.add_cube([methods_intervals2, paths_dfa], ["methods", "paths"])
        self.assertEqual(1, len(x))
        p = CanonicalIntervalSet.get_interval_set(500, 600)
        y = CanonicalHyperCubeSet(dimensions)
        y.add_cube([p, methods_intervals1, paths_dfa], ["ports", "methods", "paths"])
        y.add_cube([p, methods_intervals2, paths_dfa], ["ports", "methods", "paths"])
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

    '''
    # TODO: test with base element as CanonicalIntervalSet instead of Interval
    def test_cubes_count(self):
        x = CanonicalHyperCubeSet(dimensions)
        a1 = CanonicalIntervalSet.get_interval_set(1, 20)
        x.add_cube([a1, a1], ["src_ports", "ports"])
        print(x)
        print(len(x))
        a2 = CanonicalIntervalSet.get_interval_set(15, 40)
        x.add_cube([a2], ["ports"])
        print(x)
        print(len(x))
        a3 = CanonicalIntervalSet.get_interval_set(100, 200)
        x.add_cube([a3, get_str_dfa("PUT")], ["ports", "methods"])
        print(x)
        print(len(x))
        a4 = CanonicalIntervalSet.get_interval_set(300, 400)
        x.add_cube([get_str_dfa("GET"),get_str_dfa("a") ], ["methods", "paths"])
        print(x)
        print(len(x))

    
    def test_cubes_count_new(self):
        dim_types = ["Interval"]*20
        print(dim_types)
        chars = list(string.ascii_lowercase)
        dim_names = chars[0:20]
        print(dim_names)
        print(len(dim_names))
        print(len(dim_types))
        interval_domain = (1,100000)
        dim_domains = [interval_domain]*20
        print(dim_domains)
        interval_domain_object = CanonicalIntervalSet.get_interval_set(1, 100000)
        dim_domains_values = dict()
        for n in dim_names:
            dim_domains_values[n] =interval_domain_object
        dimensions_new = Dimensions(dim_types, dim_names, dim_domains, dim_domains_values)

        x = CanonicalHyperCubeSet(dimensions_new)
        a1 = CanonicalIntervalSet.get_interval_set(1, 20)
        x.add_cube([a1, a1], ["a", "b"])
        print(x)
        print(len(x))
        a2 = CanonicalIntervalSet.get_interval_set(15, 40)
        x.add_cube([a2], ["b"])
        print(x)
        print(len(x))
        cube = [CanonicalIntervalSet.get_interval_set(100, 200), CanonicalIntervalSet.get_interval_set(300, 400)]
        #print(str(cube[0]), str(cube[1]))
        for i in range(1, 18):
            cube_dims = [dim_names[i], dim_names[i+1]]
            x.add_cube(cube, cube_dims)
            if i<=3:
                print(x)
            #print(cube_dims)
            w= cube[0]
            y = cube[1]
            w.start+= 200
            w.end += 200
            y.start+= 200
            y.end += 200
            cube = [w, y]
            #print(str(cube[0]), str(cube[1]))
            print(f'i: {i}, x_len: {len(x)}, layers_x_len:{len(x.layers)}')
    '''

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
        methods_intervals = get_method_interval("PUT")
        x.add_cube([ports_range3, methods_intervals], ["ports", "methods"])
        x_expected_cubes = [
            [range1, ports_range2, dim_manager.get_dimension_domain_by_name("methods")],
            [range1, ports_range3, methods_intervals],
            [ports_range, CanonicalIntervalSet.get_interval_set(10, 40),
             dim_manager.get_dimension_domain_by_name("methods")],
            [ports_range, ports_range3, methods_intervals]
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

        x.add_cube([ports_range, methods_intervals, paths_dfa], ["ports", "methods", "paths"])
        x_expected_cubes.append([range1, CanonicalIntervalSet.get_interval_set(10, 14), methods_intervals, paths_dfa])
        # print(x)
        self.assertEqual(sorted(x._get_cubes_list_from_layers()), sorted(x_expected_cubes))

        ports_range4 = CanonicalIntervalSet.get_interval_set(4000, 4000)
        x.add_cube([ports_range4, methods_intervals, paths_dfa], ["ports", "methods", "paths"])
        for cube in x_expected_cubes:
            if cube == [range1, CanonicalIntervalSet.get_interval_set(10, 14), methods_intervals, paths_dfa]:
                cube[1].add_interval(CanonicalIntervalSet.Interval(4000, 4000))
        x_expected_cubes.append([ports_range, ports_range4, methods_intervals, paths_dfa])
        self.assertEqual(sorted(x._get_cubes_list_from_layers()), sorted(x_expected_cubes))
        # print(x)

        # TODO: test union for resulting cubes, by adding the missing sub-cube
        methods_dfa_all_but_put = dim_manager.get_dimension_domain_by_name("methods") - methods_intervals
        new_cube = [methods_dfa_all_but_put]
        x.add_cube(new_cube, ["methods"])
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
            [range1, range3, dim_domains_values["methods"], dim_domains_values["paths"] ],
            [range1, range4, methods_dfa_all_but_put, dim_domains_values["paths"]  ],
            [ports_range, range5, dim_domains_values["methods"], dim_domains_values["paths"] ],
            [ports_range, ports_range4, methods_dfa_all_but_put, dim_domains_values["paths"] ],
            [ports_range, range4, methods_dfa_all_but_put, dim_domains_values["paths"] ],
            [ports_range, ports_range4, get_str_dfa("PUT"), paths_dfa]
             ]
        '''
        x_expected_cubes = {
            tuple([range1, range2, methods_intervals, paths_dfa]),
            tuple([range1, range2, methods_dfa_all_but_put, dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([range1, range3, dim_manager.get_dimension_domain_by_name("methods"),
                   dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([range1, range4, methods_dfa_all_but_put, dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, range5, dim_manager.get_dimension_domain_by_name("methods"),
                   dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, ports_range4, methods_dfa_all_but_put,
                   dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, range4, methods_dfa_all_but_put, dim_manager.get_dimension_domain_by_name("paths")]),
            tuple([ports_range, ports_range4, get_method_interval("PUT"), paths_dfa])
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

    def test_eq(self):
        x = CanonicalHyperCubeSet(dimensions)
        y = CanonicalHyperCubeSet(dimensions)
        self.assertEqual(x, y)
        # print(x)
        # print(y)
        x.active_dimensions = ["ports", "methods"]
        y.active_dimensions = ["ports"]
        # print(x)
        # print(y)
        self.assertEqual(x, y)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_method_interval("PUT")
        x.add_cube([ports_range, methods_dfa], ["ports", "methods"])
        y.add_cube([ports_range], ["ports"])
        # x.cubes_list.append([ports_range, methods_dfa])
        # y.cubes_list.append([ports_range])
        # print(x)
        # print(y)
        self.assertNotEqual(x, y)
        y.clear()
        y.active_dimensions = ["ports", "methods"]
        y.add_cube([ports_range, get_method_interval("GET")], ["ports", "methods"])
        # y.cubes_list = [[ports_range, get_str_dfa("GET")]]
        # print(x)
        # print(y)
        self.assertNotEqual(x, y)
        y.clear()
        y.active_dimensions = ["ports", "methods"]
        y.add_cube([ports_range, get_method_interval("PUT")], ["ports", "methods"])
        # y.cubes_list = [[ports_range, get_str_dfa("PUT")]]
        # print(x)
        # print(y)
        self.assertEqual(x, y)

    def test_get_first_item(self):
        all = CanonicalHyperCubeSet(dimensions, True)
        item1 = all.get_first_item()
        item_str = ','.join(str(x) for x in item1)
        # print(item_str)
        self.assertTrue(item1 in all)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        methods_dfa = get_method_interval("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_dfa, paths_dfa]
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube(cube1, ["ports", "methods", "paths"])
        item2 = x.get_first_item()
        item_str = ','.join(str(x) for x in item2)
        # TODO: currently item_str is : 1,10,3,abc , and not: 1,10,PUT, abc
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
        hole2 = [get_method_interval("PUT") - get_method_interval("PUT")]
        all.add_hole(hole2, ["methods"])
        self.assertEqual(all, CanonicalHyperCubeSet(dimensions, True))
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube([])
        x.add_cube([CanonicalIntervalSet(), get_method_interval("PUT")])
        self.assertEqual(x, CanonicalHyperCubeSet(dimensions))
        x.add_cube(
            [CanonicalIntervalSet.get_interval_set(10, 20), get_method_interval("PUT") - get_method_interval("PUT")])
        self.assertEqual(x, CanonicalHyperCubeSet(dimensions))
        x.add_cube([CanonicalIntervalSet.get_interval_set(10, 20), get_method_interval("PUT")])
        self.assertNotEqual(x, CanonicalHyperCubeSet(dimensions))

    def test_iter(self):
        x = CanonicalHyperCubeSet.create_from_cube(dimensions3, [CanonicalIntervalSet.get_interval_set(1, 10)],
                                                   ["ports"])
        y = CanonicalHyperCubeSet.create_from_cube(dimensions3, [CanonicalIntervalSet.get_interval_set(100, 103)],
                                                   ["src_ports"])
        z = x | y
        for cube in iter(z):
            print(z.get_cube_str(cube))
        w = CanonicalHyperCubeSet.create_from_cube(dimensions3, [get_str_dfa("a*")], ["paths"])
        z |= w
        for cube in iter(z):
            print(z.get_cube_str(cube))
        print('---')
        w = CanonicalHyperCubeSet.create_from_cube(dimensions3, [get_str_dfa("b")], ["hosts"])
        z |= w
        for cube in iter(z):
            print(z.get_cube_str(cube))
        all = CanonicalHyperCubeSet(dimensions3, True)
        for cube in iter(all):
            print(','.join(str(x) for x in cube))

        w = CanonicalHyperCubeSet.create_from_cube(dimensions3, [
            dim_manager.get_dimension_domain_by_name("paths") - get_str_dfa("a")], ["paths"])
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
        methods_interlvas = get_method_interval("PUT")
        paths_dfa = get_str_dfa("abc")
        cube1 = [ports_range, methods_interlvas, paths_dfa]
        # TODO: define method item representation?
        item1 = [15, 15, MethodSet.all_methods_list.index('PUT'), "abc"]
        item2 = [15, 150, MethodSet.all_methods_list.index('PUT'), "abc"]
        item3 = [150, 15, MethodSet.all_methods_list.index('PUT'), "abc"]
        item4 = [15, 15, MethodSet.all_methods_list.index('PUT'), "abcd"]
        self.assertTrue(item1 in all)
        self.assertFalse(item1 in empty)
        x = CanonicalHyperCubeSet(dimensions)
        x.add_cube(cube1, ["ports", "methods", "paths"])
        self.assertTrue(item1 in x)
        self.assertFalse(item2 in x)
        self.assertTrue(item3 in x)
        self.assertFalse(item4 in x)
        y = all.copy()
        y.add_hole([paths_dfa], ["paths"])
        self.assertFalse(item2 in y)
        self.assertTrue(item4 in y)
        z = CanonicalHyperCubeSet.create_from_cube(dimensions, [ports_range, ports_range, methods_interlvas, paths_dfa],
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
        for dim in ['methods', 'paths']:
            cube_val = get_str_dfa("abc") if dim == 'paths' else get_method_interval("PUT")
            all = CanonicalHyperCubeSet(dimensions, True)
            empty = CanonicalHyperCubeSet(dimensions)
            x1 = empty.copy()
            x1.add_cube([cube_val], [dim])
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

            all_space_cube = x1._get_entire_space_cube()
            x3 = x1.copy()
            x3.add_cube(all_space_cube, dimensions)
            self.assertEqual(x3, all)
            x4 = x1.copy()
            x4.add_hole(all_space_cube, dimensions)
            self.assertEqual(x4, empty)
            short_all_space_cube = [all_space_cube[3]] if dim == 'paths' else [all_space_cube[2]]
            x5 = x1.copy()
            x5.add_cube(short_all_space_cube, [dim])
            self.assertEqual(x5, all)

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
        z.clear()

        # print(z)
        # print(x)
        res5 = x.contained_in(z)
        # print(res5)
        self.assertFalse(res5)
        z.set_all()
        res6 = x.contained_in(z)
        # print(res6)
        self.assertTrue(res6)

    def test_contained_in_new(self):
        x = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("abc")], ["paths"])
        y = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(10, 20)],
                                                   ["ports"])
        self.assertFalse(x.contained_in(y))
        self.assertFalse(y.contained_in(x))
        z = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(10, 20)],
                                                   ["ports"])
        w = CanonicalHyperCubeSet.create_from_cube(dimensions, [CanonicalIntervalSet.get_interval_set(10, 20)],
                                                   ["ports"])
        w.add_cube([CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("abc")], ["ports", "paths"])
        print(z)
        print(w)
        self.assertTrue(z.contained_in(w))
        self.assertFalse(w.contained_in(z))
        w2 = CanonicalHyperCubeSet.create_from_cube(dimensions,
                                                    [CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("abc")],
                                                    ["ports", "paths"])
        self.assertFalse(z.contained_in(w2))
        w2.add_cube([CanonicalIntervalSet.get_interval_set(10, 20)], ["ports"])
        self.assertTrue(z.contained_in(w2))

        w2.add_cube([get_str_dfa("x")], ["paths"])
        z2 = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("x")], ["paths"])
        print(z2)
        print(w2)
        self.assertTrue(z2.contained_in(w2))
        w2.add_hole([CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("x")], ["ports", "paths"])
        self.assertFalse(z2.contained_in(w2))

        a = CanonicalHyperCubeSet.create_from_cube(dimensions,
                                                   [CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("x")],
                                                   ["ports", "paths"])
        b = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("x")], ["paths"])
        self.assertTrue(a.contained_in(b))

        c = CanonicalHyperCubeSet.create_from_cube(dimensions,
                                                   [CanonicalIntervalSet.get_interval_set(10, 20), get_str_dfa("x")],
                                                   ["ports", "paths"])
        c.add_cube([CanonicalIntervalSet.get_interval_set(5, 5), get_str_dfa("y")], ["ports", "paths"])
        d = CanonicalHyperCubeSet.create_from_cube(dimensions, [get_str_dfa("x|y|z")], ["paths"])
        self.assertTrue(c.contained_in(d))

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

    def test_subtract_new(self):
        all = CanonicalHyperCubeSet(dimensions3, True)
        paths_dfa = get_str_dfa("abc")
        methods_intervals = get_method_interval("PUT")
        hosts = dim_manager.get_dimension_domain_by_name("hosts")
        hole_cube = [methods_intervals, paths_dfa, hosts]
        all.add_hole(hole_cube, ["methods", "paths", "hosts"])
        # print(all)
        res_cube_1 = (methods_intervals, dim_manager.get_dimension_domain_by_name("paths") - paths_dfa)
        res_cube_2 = (dim_manager.get_dimension_domain_by_name("methods") - methods_intervals,
                      dim_manager.get_dimension_domain_by_name("paths"))
        expected_cubes = {res_cube_1, res_cube_2}
        self.assertEqual(expected_cubes, all._get_cubes_set())

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

    # def test_basic_or_2(self):
    #     x = CanonicalHyperCubeSet(dimensions)
    #     y = CanonicalHyperCubeSet(dimensions)
    #     paths_dfa = get_str_dfa("abc")
    #     ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
    #     x.add_cube([paths_dfa], ["paths"])
    #     y.add_cube([ports_range], ["ports"])
    #     # print(x)
    #     # print(y)
    #     z_cube_expected_1 = (
    #         CanonicalIntervalSet.get_interval_set(1, 9) | CanonicalIntervalSet.get_interval_set(21, 65535), paths_dfa)
    #     z_cube_expected_2 = (
    #         CanonicalIntervalSet.get_interval_set(10, 20), dim_manager.get_dimension_domain_by_name("paths"))
    #     z = x | y
    #     # print(z)
    #     w = str(z)
    #     # failing the comparison of z actual cubes to expected cubes
    #     # the problem is that one of the cubes of z is (10-20, (abc)|/*-(abc)) which is (abc)|/* , instead of just (/*) ,
    #     # because (abc) is outside the domain
    #     # when changing paths dfa to be "/abc" the issue is resolved.
    #     # consider adding validation of cubes values within the domains.
    #     self.assertEqual({z_cube_expected_1, z_cube_expected_2}, z._get_cubes_set())
    #     # print(z)

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

    def test_basic_and(self):
        x = CanonicalHyperCubeSet(dimensions3)
        y = CanonicalHyperCubeSet(dimensions3)
        ports_range = CanonicalIntervalSet.get_interval_set(10, 20)
        ports_range1 = CanonicalIntervalSet.get_interval_set(15, 30)
        x.add_cube([ports_range, ports_range], ["src_ports", "ports"])
        y.add_cube([ports_range1, ports_range1], ["src_ports", "ports"])
        z = x & y
        res_cube = [CanonicalIntervalSet.get_interval_set(15, 20), CanonicalIntervalSet.get_interval_set(15, 20)]
        self.assertEqual(z._get_cubes_list_from_layers(), [res_cube])
        # print(z)

        x1 = CanonicalHyperCubeSet(dimensions3)
        y1 = CanonicalHyperCubeSet(dimensions3)
        paths_dfa = get_str_dfa("abc")
        paths_dfa_new = get_str_dfa("abc|a")
        x1.add_cube([paths_dfa, paths_dfa], ["paths", "hosts"])
        y1.add_cube([paths_dfa_new, paths_dfa_new], ["paths", "hosts"])
        z1 = x1 & y1
        self.assertEqual(z1, x1)
        # print(z1)

        x2 = CanonicalHyperCubeSet(dimensions3)
        y2 = CanonicalHyperCubeSet(dimensions3)
        paths_dfa = get_str_dfa("abc")
        paths_dfa_new = get_str_dfa("abc|a")
        x2.add_cube([paths_dfa], ["paths"])
        y2.add_cube([paths_dfa_new], ["paths"])
        z2 = x2 & y2
        self.assertEqual(z2, x2)
        # print(z2)

    def test_add_hole_basic(self):
        x = CanonicalHyperCubeSet(dimensions3)
        hosts_dfa = get_str_dfa("abc")
        hosts_dfa_new = get_str_dfa("abc|a")
        paths_dfa_1 = get_str_dfa("x|m")
        paths_dfa_2 = get_str_dfa("y|m")
        hosts_dfa2 = get_str_dfa("abcd")
        x.add_cube([paths_dfa_2, hosts_dfa2], ["paths", "hosts"])  # (y|m, abcd)
        res1 = {(get_str_dfa("y|m"), get_str_dfa("abcd"))}
        self.assertEqual(x._get_cubes_set(), res1)
        # print(x)
        x.add_cube([paths_dfa_1, hosts_dfa_new], ["paths", "hosts"])  # (x|m, abc)
        res2 = {(get_str_dfa("m"), get_str_dfa("a|abc|abcd")), (get_str_dfa("y"), get_str_dfa("abcd")),
                (get_str_dfa("x"), get_str_dfa("a|abc"))}
        self.assertEqual(x._get_cubes_set(), res2)
        # print(x)
        hole_dfa = get_str_dfa("m")
        x.add_hole([hole_dfa], ["paths"])
        res3 = {(get_str_dfa("y"), get_str_dfa("abcd")), (get_str_dfa("x"), get_str_dfa("a|abc"))}
        self.assertEqual(x._get_cubes_set(), res3)
        # print(x)
        hole_dfa = get_str_dfa("z")
        x.add_hole([hole_dfa], ["paths"])
        res4 = {(get_str_dfa("y"), get_str_dfa("abcd")), (get_str_dfa("x"), get_str_dfa("a|abc"))}
        # print(x)
        self.assertEqual(x._get_cubes_set(), res4)
        x.add_hole([paths_dfa_1, hosts_dfa], ["paths", "hosts"])
        # print(x)
        res5 = {(get_str_dfa("y"), get_str_dfa("abcd")), (get_str_dfa("x"), get_str_dfa("a"))}
        self.assertEqual(x._get_cubes_set(), res5)

    def test_add_cube_dfa_basic_3(self):
        x = CanonicalHyperCubeSet(dimensions3)
        hosts_dfa = get_str_dfa("abc")
        # methods_dfa_1 = get_str_dfa("x")
        paths_dfa_2 = get_str_dfa("y")
        hosts_dfa2 = get_str_dfa("abcd")
        # paths_dfa3 = get_str_dfa("abcde")
        # methods_dfa_3 = get_str_dfa("x|y|z")
        x.add_cube([hosts_dfa], ["hosts"])  # (*, abc)
        # print(x)
        res1 = {tuple([get_str_dfa("abc")])}
        self.assertEqual(x._get_cubes_set(), res1)
        x.add_cube([paths_dfa_2, hosts_dfa2], ["paths", "hosts"])  # (y, abcd)
        res2 = {(get_str_dfa("y"), get_str_dfa("abc|abcd")),
                (dim_manager.get_dimension_domain_by_name("paths") - get_str_dfa("y"), get_str_dfa("abc"))}
        self.assertEqual(x._get_cubes_set(), res2)
        # print(x)
        # TODO: test: update_layers_from_cubes_list  (sorting issue with MinDFA)

    def test_add_cube_dfa_basic_2(self):
        x = CanonicalHyperCubeSet(dimensions3)
        hosts_dfa = get_str_dfa("abc")
        paths_dfa_1 = get_str_dfa("x")
        paths_dfa_2 = get_str_dfa("y")
        hosts_dfa2 = get_str_dfa("abcd")
        hosts_dfa3 = get_str_dfa("abcde")
        paths_dfa_3 = get_str_dfa("x|y|z")

        x.add_cube([paths_dfa_1, hosts_dfa], ["paths", "hosts"])  # (x, abc)
        # print(x)
        res1 = {(get_str_dfa("x"), get_str_dfa("abc"))}
        self.assertEqual(x._get_cubes_set(), res1)
        x.add_cube([paths_dfa_2, hosts_dfa2], ["paths", "hosts"])  # (y, abcd)
        res2 = {(get_str_dfa("x"), get_str_dfa("abc")), (get_str_dfa("y"), get_str_dfa("abcd"))}
        self.assertEqual(x._get_cubes_set(), res2)
        # print(x)
        x.add_cube([paths_dfa_3, hosts_dfa3], ["paths", "hosts"])  # (x|y, abcde)
        res3 = {(get_str_dfa("x"), get_str_dfa("abc|abcde")), (get_str_dfa("y"), get_str_dfa("abcd|abcde")),
                (get_str_dfa("z"), get_str_dfa("abcde"))}
        # assert (x._get_cubes_set() == res3)
        # diff1 = x._get_cubes_set() -res3
        # diff2 = res3 - x._get_cubes_set()
        # print(f'diff1: {diff1}')
        # print(f'diff2: {diff2}')
        self.assertEqual(x._get_cubes_set(), res3)
        # print(x)

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
        x.add_cube([methods_dfa], ["methods"])
        print(x)
        '''
        # print(x)

    def test_basic_new(self):
        c = CanonicalHyperCubeSet(dimensions)
        c.add_cube([get_method_interval("PUT"), get_str_dfa("a")], ["methods", "paths"])
        c.add_cube([get_method_interval("GET"), get_str_dfa("p")], ["methods", "paths"])
        c.add_cube([get_method_interval("GET"), get_str_dfa("[p]*")], ["methods", "paths"])
        d = CanonicalHyperCubeSet(dimensions)
        d.add_cube([get_method_interval("GET"), get_str_dfa("pp")], ["methods", "paths"])
        d.add_cube([get_method_interval("GET"), get_str_dfa("[p]*")], ["methods", "paths"])
        d.add_cube([get_method_interval("PUT"), get_str_dfa("a")], ["methods", "paths"])
        self.assertEqual(c, d)

        a = CanonicalHyperCubeSet(dimensions)
        a.add_cube([CanonicalIntervalSet.get_interval_set(80, 80), get_str_dfa("abc")], ["ports", "paths"])
        a.add_cube([CanonicalIntervalSet.get_interval_set(80, 81), get_str_dfa("a")], ["ports", "paths"])
        res1 = {(CanonicalIntervalSet.get_interval_set(80, 80), get_str_dfa("a|abc")),
                (CanonicalIntervalSet.get_interval_set(81, 81), get_str_dfa("a"))}
        self.assertEqual(a._get_cubes_set(), res1)

        b = CanonicalHyperCubeSet(dimensions)
        b.add_cube([get_method_interval("GET"), get_str_dfa("p")], ["methods", "paths"])
        b.add_cube([get_method_interval("PUT"), get_str_dfa("[p]*")], ["methods", "paths"])
        # print(b)
        res2 = {(get_method_interval("GET"), get_str_dfa("p")),
                (get_method_interval("PUT"), get_str_dfa("[p]*"))}
        self.assertEqual(b._get_cubes_set(), res2)

        g = CanonicalHyperCubeSet(dimensions3)
        g.add_cube([get_method_interval("PUT"), get_str_dfa("b"), get_str_dfa("c")], ["methods", "paths", "hosts"])
        g.add_cube([get_method_interval("PUT"), get_str_dfa("e"), get_str_dfa("c")], ["methods", "paths", "hosts"])
        res3 = [[get_method_interval("PUT"), get_str_dfa("b|e"), get_str_dfa("c")]]
        self.assertEqual(g._get_cubes_list_from_layers(), res3)

        x = CanonicalHyperCubeSet(dimensions)
        methods_set_1 = get_method_interval("GET") | get_method_interval("PUT")
        methods_set_2 = get_method_interval("GET") | get_method_interval("HEAD")
        x.add_cube(
            [CanonicalIntervalSet.get_interval_set(80, 80), methods_set_1, get_str_dfa("good1|good2|some2")],
            ["ports", "methods", "paths"])
        x.add_cube(
            [CanonicalIntervalSet.get_interval_set(90, 90), methods_set_1, get_str_dfa("good1|good2|some2")],
            ["ports", "methods", "paths"])
        x.add_cube(
            [CanonicalIntervalSet.get_interval_set(1, 89), methods_set_2, get_str_dfa("bad1|bad3|some2")],
            ["ports", "methods", "paths"])
        x.add_cube([CanonicalIntervalSet.get_interval_set(91, 65535), methods_set_2], ["ports", "methods"])
        x.add_hole(
            [CanonicalIntervalSet.get_interval_set(91, 65535), methods_set_2, get_str_dfa("bad1|bad3|some2")],
            ["ports", "methods", "paths"])
        # TODO: check cubes list more precisely
        # print(x)
        self.assertEqual(len(x), 6)

        a = CanonicalHyperCubeSet(dimensions, True)
        b = CanonicalHyperCubeSet(dimensions)
        b.add_cube([get_str_dfa("bad1")], ["paths"])
        a -= b
        self.assertEqual(a._get_cubes_list_from_layers(),
                         [[dim_manager.get_dimension_domain_by_name("paths") - get_str_dfa("bad1")]])

        a = CanonicalHyperCubeSet(dimensions)
        b = CanonicalHyperCubeSet(dimensions)
        c = CanonicalHyperCubeSet(dimensions)
        a.add_cube([get_method_interval("PUT"), get_str_dfa("a")], ["methods", "paths"])
        self.assertEqual(a & a, a)
        b.add_cube([get_method_interval("PUT"), get_str_dfa("a")], ["methods", "paths"])
        b.add_cube([get_method_interval("GET"), get_str_dfa("b")], ["methods", "paths"])
        self.assertEqual(a & b, a)
        self.assertNotEqual(a, b)
        c.add_cube([methods_set_1, get_str_dfa("a|b")], ["methods", "paths"])
        self.assertEqual(a & c, a)
        self.assertEqual(b & c, b)

        a = CanonicalHyperCubeSet(dimensions)
        b = CanonicalHyperCubeSet(dimensions)
        a.add_cube([get_method_interval("PUT"), get_str_dfa("a")], ["methods", "paths"])
        a.add_cube([get_method_interval("PUT"), get_str_dfa("b")], ["methods", "paths"])
        b.add_cube([methods_set_1, get_str_dfa("a|b")], ["methods", "paths"])
        self.assertTrue(a.contained_in(b))
        self.assertFalse(b.contained_in(a))

        a = CanonicalHyperCubeSet(dimensions)
        b = CanonicalHyperCubeSet(dimensions)
        c = CanonicalHyperCubeSet(dimensions)
        a.add_cube([get_method_interval("PUT"), get_str_dfa("a")], ["methods", "paths"])
        a.add_cube([get_method_interval("PUT"), get_str_dfa("b")], ["methods", "paths"])
        c.add_cube([get_method_interval("GET"), get_str_dfa("a")], ["methods", "paths"])
        c.add_cube([get_method_interval("GET"), get_str_dfa("b")], ["methods", "paths"])
        b.add_cube([methods_set_1, get_str_dfa("a|b")], ["methods", "paths"])
        self.assertEqual(a | c, b)
        empty = CanonicalHyperCubeSet(dimensions)
        self.assertEqual(a - a, empty)
        self.assertEqual(b - c, a)
        self.assertEqual(b - a, c)

    def test_method_set_copy(self):
        a = get_method_interval("GET")
        b = a.copy()
        self.assertNotEqual(id(a), id(b))
        self.assertNotEqual(id(a.interval_set), id(b.interval_set))
        self.assertEqual(str(a), str(b))

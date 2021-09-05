import unittest

from MultiLayerPropertiesSet import RequestAttrs


class TestMultiLayerPropertiesSetMethods(unittest.TestCase):

    def test_basic(self):

        a = RequestAttrs()

        self.assertTrue(not a)
        b = RequestAttrs(True)
        self.assertTrue(b)
        c = a.copy()
        c.set_methods(None, {'GET'})
        print(a)
        print(b)
        print(c)

        # test methods/notMethods
        a.set_methods({'GET'}, None)
        a.add_methods({'GET'})  # does nothing
        a.remove_methods({'PUT'})  # does nothing
        self.assertTrue(a)
        print(a)
        c = b - a
        print(c)

        self.assertTrue(c | a == b)
        self.assertTrue(c != b)
        self.assertTrue(a != b)
        self.assertTrue(a.contained_in(b))
        self.assertTrue(c.contained_in(b))
        self.assertFalse(b.contained_in(c))
        print(c.print_diff(a, 'c', 'a'))

        d = c.copy()
        d.add_methods({'GET'})
        self.assertTrue(d == b)
        self.assertTrue(d != c)

        e = c & a
        self.assertTrue(e == RequestAttrs())
        self.assertTrue(a & b == a)

        a |= c
        self.assertTrue(a == b)

        # ToDo: add tests for operation.notMethods

        x = RequestAttrs()
        y = RequestAttrs(True)
        self.assertTrue(not x)
        self.assertTrue(y)

        # unlimited attributes - basic construction
        x.add_paths(False, {'path_1', 'path_1'})
        x.add_paths(False, {'path_1', 'path_2'})
        x.remove_paths(False, {'path_1', 'path_3'})
        x.remove_paths(False, {'path_2'})
        x.remove_paths(disallow_all=True)
        x.add_paths(False, {'path_2'})
        x.add_paths(allow_all=True)
        x.remove_paths(False, {'path_1', 'path_3'})
        x.add_paths(False, {'path_1'})
        x.add_paths(False, {'path_3'})
        x.set_hosts(None, {'abc.com'})

        # test operations on sets with positive attributes
        x = RequestAttrs()
        y = RequestAttrs()
        x.set_paths({'path_1', 'path_2'}, None)
        y.set_paths({'path_1', 'path_3'}, None)
        x.add_paths(False, {'path_3'})

        z = y - x
        z = x + y
        v = y.copy()
        y += x
        self.assertTrue(y == z)
        self.assertFalse(v == z)
        v = x & y
        self.assertTrue(v == y)

        # test operations - one set with positive attributes and another set with negative attributes
        y.add_paths(allow_all=True)
        y.remove_paths(False, {'path_1', 'path_3'})
        z = x + y
        z = y + x
        z = x - y
        all_paths = RequestAttrs().add_paths(allow_all=True)
        self.assertTrue(z + y == all_paths)
        z = y - x
        y -= x
        self.assertTrue(y == z)
        v = x & y
        self.assertFalse(v)
        self.assertTrue(v.contained_in(x))

        # test operations - both sets with negative attributes
        y.add_paths(allow_all=True)
        y.remove_paths(False, {'path_1', 'path_3'})
        x.add_paths(allow_all=True)
        x.remove_paths(False, {'path_1', 'path_2'})
        z = x + y
        v = x | y
        self.assertTrue(v == z)
        z = x - y
        z = y - x
        v = x & y
        self.assertTrue(v.contained_in(x))

        # test operations - one set allows all, other set with negative attributes
        x.add_paths(allow_all=True)
        z = x + y
        z = y + x
        z = x - y
        z = y - x
        v = y.copy()
        v -= v
        self.assertFalse(v)
        v |= y
        self.assertTrue(v == y)
        v = x & y
        y &= y
        self.assertTrue(v == y)

        # test operations - one set allows all, other set with positive attributes
        y.remove_paths(disallow_all=True)
        y.add_paths(False, {'path_1', 'path_3'})
        z = x + y
        z = y + x
        z = x - y
        z = y - x
        v = x & y

        # test operations - one set allows nothing, other set with negative attributes
        x = RequestAttrs()
        z = x + y
        z = y + x
        z = x - y
        z = y - x
        self.assertTrue(z == y)

        y.add_paths(allow_all=True)
        y.remove_paths(False, {'path_1', 'path_2'})
        z = x + y
        z = y + x
        z = x - y
        z = y - x

        print(z)

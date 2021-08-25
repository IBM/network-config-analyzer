import unittest

from MultiLayerPropertiesSet import RequestAttrs


class TestMultiLayerPropertiesSetMethods(unittest.TestCase):

    def test_basic(self):

        a = RequestAttrs()

        self.assertTrue(not a)
        b = RequestAttrs(True)
        self.assertTrue(b)
        print(a)
        print(b)

        a.set_methods({'GET'})
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

        x = RequestAttrs()
        y = RequestAttrs()
        x.add_paths(False, {'path_1', 'path_2'})
        y.add_paths(False, {'path_1', 'path_3'})
        x.add_paths(False, {'path_3'})

        z = y - x
        z = x + y
        v = y.copy()
        y += x
        self.assertTrue(y == z)
        self.assertFalse(v == z)
        v = x & y
        self.assertTrue(v == y)

        y.add_paths(allow_all=True)
        y.remove_paths(False, {'path_1', 'path_3'})
        z = x + y
        z = y + x
        z = x - y
        z = y - x
        y -= x
        self.assertTrue(y == z)
        v = x & y
        self.assertFalse(v)
        self.assertTrue(v.contained_in(x))

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

        y.remove_paths(disallow_all=True)
        y.add_paths(False, {'path_1', 'path_3'})
        z = x + y
        z = y + x
        z = x - y
        z = y - x
        v = x & y

        x = RequestAttrs()
        z = x + y
        z = y + x
        z = x - y
        z = y - x

        y.add_paths(allow_all=True)
        y.remove_paths(False, {'path_1', 'path_2'})
        z = x + y
        z = y + x
        z = x - y
        z = y - x

        print(z)



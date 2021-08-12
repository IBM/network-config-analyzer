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
        a.add_methods({"GET"})
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
        print(c.print_diff(a, "c", "a"))

        d = c.copy()
        d.add_methods({"GET"})
        self.assertTrue(d == b)
        self.assertTrue(d != c)

        e = c & a
        self.assertTrue(e == RequestAttrs())
        self.assertTrue(a & b == a)

        a |= c
        self.assertTrue(a == b)





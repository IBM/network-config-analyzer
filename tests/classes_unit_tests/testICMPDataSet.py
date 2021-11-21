import unittest

from ICMPDataSet import ICMPDataSet


class TestICMPDataSet(unittest.TestCase):
    def test_basic(self):
        x = ICMPDataSet()
        y = ICMPDataSet()
        w = ICMPDataSet()
        x. add_all_but_given_pair(20, None)
        y.add_all()
        w. add_all_but_given_pair(20, 50)
        diff_str = x.print_diff(y, "x", "y")
        print(diff_str)

        z = x.get_properties_obj()
        print(z)
        z = y.get_properties_obj()
        print(z)
        z = w.get_properties_obj()
        print(z)
        print(x)
        print(y)
        print(w)



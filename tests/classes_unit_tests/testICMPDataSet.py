import unittest

from ICMPDataSet import ICMPDataSet


class TestICMPDataSet(unittest.TestCase):
    def test_basic(self):
        x = ICMPDataSet()
        y = ICMPDataSet()
        w = ICMPDataSet()
        f = ICMPDataSet()
        f.add_to_set(100,230)
        print(f)
        z = f.get_properties_obj()
        print(z)

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



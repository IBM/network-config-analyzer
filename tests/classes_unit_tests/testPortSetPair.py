from CanonicalIntervalSet import CanonicalIntervalSet
from PortSet import PortSet
from PortSet import TcpProperties

import unittest


class TestPortSetPairMethods(unittest.TestCase):

    def test_and(self):
        a = PortSet(False)
        a.add_port("A")
        a.remove_port("B")

        b = PortSet(False)
        b.add_port_range(80, 100)

        first = TcpProperties(b, a)

        c = PortSet(False)
        c.add_port("A")
        c.add_port("M")
        c.remove_port("C")

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = TcpProperties(d, c)

        res = first & second
        res_src_port_set = CanonicalIntervalSet()
        res_src_port_set.add_interval(CanonicalIntervalSet.Interval(85, 90))
        self.assertTrue(res.named_ports['A'] == res_src_port_set)
        self.assertTrue("B" in res.excluded_named_ports)
        self.assertTrue("C" in res.excluded_named_ports)
        self.assertTrue("M" not in res.named_ports)

    def test_or(self):
        a = PortSet(False)
        a.add_port("A")
        a.remove_port("B")

        b = PortSet(False)
        b.add_port_range(80, 100)

        first = TcpProperties(b, a)

        c = PortSet(False)
        c.add_port("A")
        c.add_port("M")
        c.add_port("B")
        c.remove_port("C")

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = TcpProperties(d, c)

        res = first | second

        res_src_port_set1 = CanonicalIntervalSet()
        res_src_port_set1.add_interval(CanonicalIntervalSet.Interval(80, 100))
        res_src_port_set2 = CanonicalIntervalSet()
        res_src_port_set2.add_interval(CanonicalIntervalSet.Interval(85, 90))
        res_src_port_set3 = CanonicalIntervalSet()
        res_src_port_set3.add_interval(CanonicalIntervalSet.Interval(1, 84))
        res_src_port_set3.add_interval(CanonicalIntervalSet.Interval(91, 65536))
        self.assertTrue(res.named_ports['A'] == res_src_port_set1)
        self.assertTrue(res.named_ports['B'] == res_src_port_set2)
        self.assertTrue(res.named_ports['M'] == res_src_port_set2)
        self.assertTrue(res.excluded_named_ports['B'] == res_src_port_set3)

    def test_sub(self):
        a = PortSet(False)
        a.add_port("A")
        a.remove_port("B")

        b = PortSet(False)
        b.add_port_range(80, 100)

        first = TcpProperties(b, a)

        c = PortSet(False)
        c.add_port("A")
        c.add_port("M")
        c.add_port("B")
        c.remove_port("C")

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = TcpProperties(d, c)

        res = first - second

        res_src_port_set1 = CanonicalIntervalSet()
        res_src_port_set1.add_interval(CanonicalIntervalSet.Interval(80, 84))
        res_src_port_set1.add_interval(CanonicalIntervalSet.Interval(91, 100))
        res_src_port_set2 = CanonicalIntervalSet()
        res_src_port_set2.add_interval(CanonicalIntervalSet.Interval(85, 90))
        res_src_port_set3 = CanonicalIntervalSet()
        res_src_port_set3.add_interval(CanonicalIntervalSet.Interval(1, 65536))

        self.assertTrue(res.named_ports['A'] == res_src_port_set1)
        self.assertTrue(res.excluded_named_ports['A'] == res_src_port_set2)
        self.assertTrue(res.excluded_named_ports['B'] == res_src_port_set3)
        self.assertTrue(res.excluded_named_ports['M'] == res_src_port_set2)


if __name__ == '__main__':
    unittest.main()

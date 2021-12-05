from CanonicalIntervalSet import CanonicalIntervalSet
from PortSet import PortSet
from TcpLikeProperties import TcpLikeProperties

import unittest


class TestNamedPorts(unittest.TestCase):
    def test_k8s_flow(self):
        """
        dest ports with named ports, and 'or' between Tcp properties with named ports
        """
        src_res_ports = PortSet(True)
        dst_res_ports = PortSet()
        dst_res_ports.add_port("x")
        tcp_properties1 = TcpLikeProperties(src_res_ports, dst_res_ports)
        dst_res_ports2 = PortSet()
        dst_res_ports2.add_port("y")
        tcp_properties2 = TcpLikeProperties(src_res_ports, dst_res_ports2)
        tcp_properties_res = tcp_properties1 | tcp_properties2
        named_ports_dict = {"x": (15, 6), "z": (20, 6), "y": (16, 6)}
        tcp_properties_res.convert_named_ports(named_ports_dict, 6)
        #print(tcp_properties_res)
        cubes_list = tcp_properties_res._get_cubes_list_from_layers()
        expected_res_cubes = [[CanonicalIntervalSet.get_interval_set(15,16)]]
        self.assertEqual(expected_res_cubes, cubes_list)

    def test_calico_flow_1(self):
        """
        dest ports containing only positive named ports
        """
        src_res_ports = PortSet()
        dst_res_ports = PortSet()
        src_res_ports.add_port_range(1, 100)
        dst_res_ports.add_port("x")
        dst_res_ports.add_port("y")
        dst_res_ports.add_port("z")
        dst_res_ports.add_port("w")
        tcp_properties = TcpLikeProperties(src_res_ports, dst_res_ports)
        tcp_properties_2 = tcp_properties.copy()

        self.assertTrue(tcp_properties.has_named_ports())
        self.assertEqual(tcp_properties.get_named_ports(), {"x","y","z", "w"})
        named_ports_dict = {"x": (15, 6), "z": (20, 6), "y": (200, 17)}
        tcp_properties.convert_named_ports(named_ports_dict, 6)
        #print(tcp_properties)
        expected_res_cubes = {(CanonicalIntervalSet.get_interval_set(1,100), CanonicalIntervalSet.get_interval_set(15,15) | CanonicalIntervalSet.get_interval_set(20,20))}
        self.assertEqual(expected_res_cubes, tcp_properties._get_cubes_set())

        self.assertTrue(tcp_properties_2.has_named_ports())
        self.assertEqual(tcp_properties_2.get_named_ports(), {"x","y","z", "w"})
        tcp_properties_2.convert_named_ports(named_ports_dict, 17)
        #print(tcp_properties_2)
        expected_res_cubes = {(CanonicalIntervalSet.get_interval_set(1,100), CanonicalIntervalSet.get_interval_set(200,200))}
        self.assertEqual(expected_res_cubes, tcp_properties_2._get_cubes_set())

    def test_calico_flow_2(self):
        """
        dest ports containing only negative named ports
        """
        src_res_ports = PortSet()
        not_ports = PortSet()
        not_ports.add_port("x")
        not_ports.add_port("y")
        not_ports.add_port("z")
        not_ports.add_port("w")
        dst_res_ports = PortSet(True)
        dst_res_ports -= not_ports
        src_res_ports.add_port_range(1, 100)
        tcp_properties = TcpLikeProperties(src_res_ports, dst_res_ports)
        tcp_properties_2 = tcp_properties.copy()

        self.assertTrue(tcp_properties.has_named_ports())
        self.assertEqual(tcp_properties.get_named_ports(), {"x","y","z", "w"})
        named_ports_dict = {"x": (15, 6), "z": (20, 6), "y": (200, 17)}
        tcp_properties.convert_named_ports(named_ports_dict, 6)
        #print(tcp_properties)
        expected_res_cubes = {(CanonicalIntervalSet.get_interval_set(1,100),
                               CanonicalIntervalSet.get_interval_set(1,14) |
                               CanonicalIntervalSet.get_interval_set(16,19) |
                               CanonicalIntervalSet.get_interval_set(21,65535))}
        self.assertEqual(expected_res_cubes, tcp_properties._get_cubes_set())

        self.assertTrue(tcp_properties_2.has_named_ports())
        self.assertEqual(tcp_properties_2.get_named_ports(), {"x","y","z", "w"})
        tcp_properties_2.convert_named_ports(named_ports_dict, 17)
        #print(tcp_properties_2)
        expected_res_cubes = {(CanonicalIntervalSet.get_interval_set(1,100),
                               CanonicalIntervalSet.get_interval_set(1,199) |
                               CanonicalIntervalSet.get_interval_set(201,65535))}
        self.assertEqual(expected_res_cubes, tcp_properties_2._get_cubes_set())









'''
class TestPortSetPairMethods(unittest.TestCase):

    def test_and(self):
        a = PortSet(False)
        a.add_port("A")

        b = PortSet(False)
        b.add_port_range(80, 100)

        first = TcpLikeProperties(b, a)

        c = PortSet(False)
        c.add_port(1)
        c.add_port(2)
        c.remove_port(1)

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = TcpLikeProperties(d, c)

        res = first & second
        res_src_port_set = CanonicalIntervalSet()
        res_src_port_set.add_interval(CanonicalIntervalSet.Interval(80, 100))
        self.assertTrue(res.named_ports['A'] == res_src_port_set)
        self.assertTrue(1 not in res.named_ports)

    def test_or(self):
        a = PortSet(False)
        a.add_port("A")
        a.remove_port("B")

        b = PortSet(False)
        b.add_port_range(80, 100)

        first = TcpLikeProperties(b, a)

        c = PortSet(False)
        c.add_port(1)
        c.add_port(2)
        c.add_port(3)
        c.remove_port(3)

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = TcpLikeProperties(d, c)

        res = first | second

        res_src_port_set1 = CanonicalIntervalSet()
        res_src_port_set1.add_interval(CanonicalIntervalSet.Interval(80, 100))
        res_src_port_set2 = CanonicalIntervalSet()
        res_src_port_set2.add_interval(CanonicalIntervalSet.Interval(85, 90))
        res_src_port_set3 = CanonicalIntervalSet()
        res_src_port_set3.add_interval(CanonicalIntervalSet.Interval(1, 65535))
        self.assertTrue(res.named_ports['A'] == res_src_port_set1)
        self.assertTrue(res.excluded_named_ports['B'] == res_src_port_set3)

    def test_sub(self):
        a = PortSet(False)
        a.add_port("A")

        b = PortSet(False)
        b.add_port_range(80, 100)

        first = TcpLikeProperties(b, a)

        c = PortSet(False)
        c.add_port(1)
        c.add_port(2)
        c.add_port(3)
        c.remove_port(2)

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = TcpLikeProperties(d, c)

        res = first - second

        res_src_port_set1 = CanonicalIntervalSet()
        res_src_port_set1.add_interval(CanonicalIntervalSet.Interval(80, 100))
        res_src_port_set2 = CanonicalIntervalSet()
        res_src_port_set2.add_interval(CanonicalIntervalSet.Interval(85, 90))
        res_src_port_set3 = CanonicalIntervalSet()
        res_src_port_set3.add_interval(CanonicalIntervalSet.Interval(1, 65535))

        self.assertTrue(res.named_ports['A'] == res_src_port_set1)
'''

if __name__ == '__main__':
    unittest.main()

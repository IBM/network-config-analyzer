import unittest
from nca.CoreDS.PortSet import PortSet
from nca.CoreDS.ConnectivityCube import ConnectivityCube
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import PeerSet, BasePeerSet, Pod
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.Resources.OtherResources.K8sNamespace import K8sNamespace


class TestNamedPorts(unittest.TestCase):

    def test_optimized_flow(self):
        default_namespace = K8sNamespace("default")
        pod_a = Pod("A", default_namespace)
        pod_a.add_named_port("x", 400, "UDP")
        pod_a.add_named_port("z", 600, "TCP")
        BasePeerSet().add_peer(pod_a)
        pod_b = Pod("B", default_namespace)
        pod_b.add_named_port("y", 500, "UDP")
        pod_b.add_named_port("w", 700, "TCP")
        BasePeerSet().add_peer(pod_b)
        pod_c = Pod("C", default_namespace)
        pod_c.add_named_port("x", 400, "UDP")
        pod_c.add_named_port("y", 500, "UDP")
        BasePeerSet().add_peer(pod_c)
        pod_d = Pod("D", default_namespace)
        pod_d.add_named_port("other_port", 800, "UDP")
        BasePeerSet().add_peer(pod_d)

        src_peers = PeerSet({pod_a, pod_c, pod_d})
        dst_peers = PeerSet({pod_a, pod_b, pod_c, pod_d})
        src_ports = PortSet.make_port_set_with_range(1, 100)
        dst_ports = PortSet.make_port_set_with_range(200, 300)
        dst_ports.add_port("x")
        dst_ports.add_port("y")
        dst_ports.add_port("z")
        dst_ports.add_port("w")
        conn_cube = ConnectivityCube.make_from_dict({"src_peers": src_peers, "dst_peers": dst_peers,
                                                     "src_ports": src_ports, "dst_ports": dst_ports,
                                                     "protocols": ProtocolSet.get_protocol_set_with_single_protocol("TCP")})
        props_with_tcp = ConnectivityProperties.make_conn_props(conn_cube)
        tcp_ports_for_pod_a = PortSet.make_port_set_with_range(200, 300)
        tcp_ports_for_pod_a.add_port_range(600, 600)
        tcp_ports_for_pod_b = PortSet.make_port_set_with_range(200, 300)
        tcp_ports_for_pod_b.add_port_range(700, 700)

        reference_props_with_tcp = \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": PeerSet({pod_a}),
                                                              "src_ports": src_ports, "dst_ports": tcp_ports_for_pod_a})
        reference_props_with_tcp |= \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": PeerSet({pod_b}),
                                                              "src_ports": src_ports, "dst_ports": tcp_ports_for_pod_b})
        reference_props_with_tcp |= \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": PeerSet({pod_c, pod_d}),
                                                              "src_ports": src_ports,
                                                              "dst_ports": PortSet.make_port_set_with_range(200, 300)})
        reference_props_with_tcp &= \
            ConnectivityProperties.make_conn_props_from_dict({"protocols": ProtocolSet.get_protocol_set_with_single_protocol("TCP")})

        self.assertEqual(props_with_tcp, reference_props_with_tcp)
        '''
        {'src_peers': 'default/D,default/A,default/C', 'dst_peers': 'default/A', 'protocols': 'TCP', 'src_ports': '1-100', 'dst_ports': '200-300,600'},
        {'src_peers': 'default/D,default/A,default/C', 'dst_peers': 'default/B', 'protocols': 'TCP', 'src_ports': '1-100', 'dst_ports': '200-300,700'},
        {'src_peers': 'default/D,default/A,default/C', 'dst_peers': 'default/D,default/C', 'protocols': 'TCP', 'src_ports': '1-100', 'dst_ports': '200-300'}
        '''
        conn_cube = ConnectivityCube.make_from_dict({"src_peers": src_peers, "dst_peers": dst_peers,
                                                     "src_ports": src_ports, "dst_ports": dst_ports,
                                                     "protocols": ProtocolSet.get_protocol_set_with_single_protocol("UDP")})
        props_with_udp = ConnectivityProperties.make_conn_props(conn_cube)
        udp_ports_for_pod_a = PortSet.make_port_set_with_range(200, 300)
        udp_ports_for_pod_a.add_port_range(400, 400)
        udp_ports_for_pod_b = PortSet.make_port_set_with_range(200, 300)
        udp_ports_for_pod_b.add_port_range(500, 500)
        udp_ports_for_pod_c = PortSet.make_port_set_with_range(200, 300)
        udp_ports_for_pod_c.add_port_range(400, 400)
        udp_ports_for_pod_c.add_port_range(500, 500)
        udp_ports_for_pod_d = PortSet.make_port_set_with_range(200, 300)

        reference_props_with_udp = \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": PeerSet({pod_a}),
                                                              "src_ports": src_ports, "dst_ports": udp_ports_for_pod_a})
        reference_props_with_udp |= \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": PeerSet({pod_b}),
                                                              "src_ports": src_ports, "dst_ports": udp_ports_for_pod_b})
        reference_props_with_udp |= \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": PeerSet({pod_c}),
                                                              "src_ports": src_ports, "dst_ports": udp_ports_for_pod_c})
        reference_props_with_udp |= \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": PeerSet({pod_d}),
                                                              "src_ports": src_ports, "dst_ports": udp_ports_for_pod_d})
        reference_props_with_udp &= \
            ConnectivityProperties.make_conn_props_from_dict({"protocols": ProtocolSet.get_protocol_set_with_single_protocol("UDP")})
        self.assertEqual(props_with_udp, reference_props_with_udp)

        '''
        {'src_peers': 'default/C,default/A,default/D', 'dst_peers': 'default/C', 'protocols': 'UDP', 'src_ports': '1-100', 'dst_ports': '200-300,400,500'},
        {'src_peers': 'default/C,default/A,default/D', 'dst_peers': 'default/A', 'protocols': 'UDP', 'src_ports': '1-100', 'dst_ports': '200-300,400'},
        {'src_peers': 'default/C,default/A,default/D', 'dst_peers': 'default/B', 'protocols': 'UDP', 'src_ports': '1-100', 'dst_ports': '200-300,500'},
        {'src_peers': 'default/C,default/A,default/D', 'dst_peers': 'default/D', 'protocols': 'UDP', 'src_ports': '1-100', 'dst_ports': '200-300'}
        '''

'''
class TestPortSetPairMethods(unittest.TestCase):

    def test_and(self):
        a = PortSet(False)
        a.add_port("A")

        b = PortSet(False)
        b.add_port_range(80, 100)

        first = ConnectivityProperties(b, a)

        c = PortSet(False)
        c.add_port(1)
        c.add_port(2)
        c.remove_port(1)

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = ConnectivityProperties(d, c)

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

        first = ConnectivityProperties(b, a)

        c = PortSet(False)
        c.add_port(1)
        c.add_port(2)
        c.add_port(3)
        c.remove_port(3)

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = ConnectivityProperties(d, c)

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

        first = ConnectivityProperties(b, a)

        c = PortSet(False)
        c.add_port(1)
        c.add_port(2)
        c.add_port(3)
        c.remove_port(2)

        d = PortSet(False)
        d.add_port_range(85, 90)

        second = ConnectivityProperties(d, c)

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

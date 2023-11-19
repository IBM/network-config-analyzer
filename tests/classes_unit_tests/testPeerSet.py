import unittest
from nca.CoreDS.Peer import PeerSet, Pod, IpBlock
from nca.Resources.SpecialResources.K8sNamespace import K8sNamespace


class TestPeerSetMethods(unittest.TestCase):

    def test_eq(self):
        default_namespace = K8sNamespace('default')
        pod_a = Pod('A', default_namespace)
        ip1 = IpBlock("1.2.3.0/24")
        ip2 = IpBlock("1.2.3.0/32")
        ip3 = ip1 - ip2
        set1 = PeerSet({pod_a, ip1})
        set2 = PeerSet({pod_a, ip2, ip3})
        self.assertTrue(set1 == set2)

    def test_and(self):
        default_namespace = K8sNamespace('default')
        pod_a = Pod('A', default_namespace)
        pod_b = Pod('B', default_namespace)
        ip1 = IpBlock("1.2.3.0/24")
        ip2 = IpBlock("1.2.3.0/32")
        pod_set_1 = {pod_a, pod_b, ip2}
        pod_set_2 = {pod_a, ip1}
        a = PeerSet(pod_set_1)
        b = PeerSet(pod_set_2)
        res1 = a & b
        self.assertTrue(res1 == PeerSet({pod_a, ip2}))
        a &= b
        self.assertTrue(a == res1)

    def test_subtract(self):
        self.assertTrue(True)
        default_namespace = K8sNamespace('default')
        pod_a = Pod('A', default_namespace)
        ip1 = IpBlock("1.2.3.0/24")
        ip2 = IpBlock("1.2.3.0/32")
        ip3 = ip1 - ip2
        set1 = PeerSet({pod_a, ip1})
        set2 = PeerSet({pod_a, ip2})
        set3 = PeerSet({ip3})
        self.assertTrue(set1-set2 == set3)


    def test_or(self):
        default_namespace = K8sNamespace('default')
        pod_a = Pod('A', default_namespace)
        pod_b = Pod('B', default_namespace)
        ip1 = IpBlock("1.2.3.0/24")
        ip2 = IpBlock("1.2.3.0/32")
        ip3 = ip1 - ip2
        set1 = PeerSet({pod_a, pod_b, ip1})
        set2 = PeerSet({pod_a, ip2})
        set3 = PeerSet({pod_b, ip3})
        self.assertTrue(set2 | set3 == set1)
        set2 |= set3
        self.assertTrue(set2 == set1)

    def test_get_peer_set(self):
        ip1 = IpBlock("1.2.3.0/24")
        ip1_set = PeerSet({ip1})
        self.assertTrue(ip1_set == ip1.get_peer_set())
        self.assertTrue(PeerSet() == (ip1-ip1).get_peer_set())

'''
currently the following scenarios are not supported by the PeerSet.__contains__ method: 

    # item of ipBlock may consist of several intervals, which may be contained in separate ip-block elements in peerSet
    def test_contains(self):
        ip_block_item = IpBlock("198.51.100.0/22") | IpBlock("203.0.113.0/25")
        peerset1 = PeerSet({IpBlock("203.0.113.0/24"), IpBlock("198.51.100.0/22"), IpBlock("198.51.200.0/27"), IpBlock("203.0.115.0/29")})
        self.assertTrue(ip_block_item in peerset1)

    # peer set is not a canonical interval set => may contain consecutive ip-blocks
    def test_contains_2(self):
        ip_block = IpBlock("100.0.0.0/31")
        peerset = PeerSet({IpBlock("100.0.0.0/32"), IpBlock("100.0.0.0/31")})
        self.assertTrue(ip_block in peerset)
'''

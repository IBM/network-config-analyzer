import unittest

from MultiLayerPropertiesSet import MultiLayerPropertiesSet, RequestAttrs
from PortSet import PortSetPair, PortSet


class TestMultiLayerPropertiesSetMethods(unittest.TestCase):

    def test_basic_1(self):
        port_set = PortSet()
        port_set.add_port(50)
        port_set.add_port(60)
        port_set_pair = PortSetPair(PortSet(True), port_set)
        method_get = RequestAttrs().add_methods({"GET"})

        a = MultiLayerPropertiesSet()
        self.assertTrue(not a)
        print(f'a: {a}')

        b = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        self.assertTrue(b)
        print(f'b: {b}')

        c = MultiLayerPropertiesSet(port_set_pair)
        self.assertTrue(c)
        print(f'c: {c}')

        d = MultiLayerPropertiesSet(port_set_pair, method_get)
        self.assertTrue(d)
        print(f'd: {d}')

        e = MultiLayerPropertiesSet(port_set_pair, RequestAttrs(True))
        self.assertTrue(e)
        print(f'e: {e}')

        f = MultiLayerPropertiesSet(port_set_pair, RequestAttrs())
        self.assertTrue(f)
        print(f'f: {f}')

        g = MultiLayerPropertiesSet(request_attributes=method_get)
        self.assertTrue(not g)
        print(f'g: {g}')

        h = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)), request_attributes=method_get)
        self.assertTrue(h)
        print(f'h: {h}')

    def test_contained_in(self):
        port_set = PortSet()
        port_set.add_port(50)
        port_set.add_port(60)
        port_set_pair = PortSetPair(PortSet(True), port_set)
        method_get = RequestAttrs().add_methods({"GET"})
        methods_get_put = RequestAttrs().add_methods({"GET", "PUT"})

        b = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        c = MultiLayerPropertiesSet(port_set_pair)
        d = MultiLayerPropertiesSet(port_set_pair, method_get)
        d2 = MultiLayerPropertiesSet(port_set_pair, methods_get_put)

        self.assertTrue(b.contained_in(b))
        self.assertTrue(c.contained_in(b))
        self.assertFalse(b.contained_in(c))
        self.assertTrue(d.contained_in(d))
        self.assertTrue(d.contained_in(d2))
        self.assertFalse(d2.contained_in(d))

    def test_contained_in_2(self):
        port_set = PortSet()
        port_set.add_port_range(50, 60)
        port_set_2 = PortSet()
        port_set_2.add_port_range(40, 55)
        port_set_3 = PortSet()
        port_set_3.add_port_range(56, 70)
        port_set_4 = PortSet()
        port_set_4.add_port_range(57, 70)
        port_set_5 = PortSet()
        port_set_5.add_port(56)
        port_set_pair = PortSetPair(PortSet(True), port_set)
        method_get = RequestAttrs().add_methods({"GET"})
        methods_get_put = RequestAttrs().add_methods({"GET", "PUT"})
        a = MultiLayerPropertiesSet(port_set_pair, method_get)
        b = MultiLayerPropertiesSet()
        b.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_2)] = method_get
        b.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_3)] = methods_get_put
        self.assertTrue(a.contained_in(b))
        self.assertFalse(b.contained_in(a))

        c = MultiLayerPropertiesSet()
        c.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_2)] = method_get
        c.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_4)] = methods_get_put
        self.assertFalse(a.contained_in(c))
        c.plain_TCP_allowed_ports = PortSetPair(PortSet(True), port_set_5)
        self.assertTrue(a.contained_in(c))

        a = MultiLayerPropertiesSet(port_set_pair, methods_get_put)
        self.assertFalse(a.contained_in(b))
        f = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        self.assertTrue(a.contained_in(f))

    def test_intersection(self):
        port_set = PortSet()
        port_set.add_port_range(50, 60)
        port_set_2 = PortSet()
        port_set_2.add_port_range(40, 55)
        port_set_3 = PortSet()
        port_set_3.add_port_range(56, 70)
        port_set_4 = PortSet()
        port_set_4.add_port_range(57, 70)
        port_set_5 = PortSet()
        port_set_5.add_port(56)
        port_set_pair = PortSetPair(PortSet(True), port_set)
        method_get = RequestAttrs().add_methods({"GET"})
        methods_get_put = RequestAttrs().add_methods({"GET", "PUT"})

        a = MultiLayerPropertiesSet(port_set_pair, method_get)
        b = a & a
        print(b)
        print(a)
        print(a & a)
        self.assertTrue(a == a & a)
        c = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        print('---')
        print(a)
        print(a & c)
        print(c & a)
        self.assertTrue(a == c & a)
        self.assertTrue(a == a & c)

        d = MultiLayerPropertiesSet()
        d.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_2)] = method_get
        d.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_3)] = methods_get_put
        e = a & d
        print(e)

    def test_or(self):
        port_set = PortSet()
        port_set.add_port_range(50, 60)
        port_set_2 = PortSet()
        port_set_2.add_port_range(40, 55)
        port_set_3 = PortSet()
        port_set_3.add_port_range(56, 70)
        port_set_4 = PortSet()
        port_set_4.add_port_range(57, 70)
        port_set_5 = PortSet()
        port_set_5.add_port(56)
        port_set_6 = PortSet()
        port_set_6.add_port_range(56, 60)
        port_set_7 = PortSet()
        port_set_7.add_port_range(50, 55)
        port_set_pair = PortSetPair(PortSet(True), port_set)
        method_get = RequestAttrs().add_methods({"GET"})
        methods_get_put = RequestAttrs().add_methods({"GET", "PUT"})
        method_put = RequestAttrs().add_methods({"PUT"})

        a = MultiLayerPropertiesSet(port_set_pair, method_get)
        b = a | a
        print(b)
        print(a)
        self.assertTrue(a == b)
        self.assertTrue(b == a)
        c = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        print(c)
        print(c | a)
        print(a | c)
        self.assertTrue(c == a | c)
        self.assertTrue(c == c | a)

        d = MultiLayerPropertiesSet()
        d.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_2)] = method_get
        d.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_3)] = methods_get_put
        print(d)
        print(a | d)
        self.assertTrue(a|d == d)
        self.assertTrue(d | a == d)


        print('---')
        e = MultiLayerPropertiesSet(port_set_pair, method_get)
        f = MultiLayerPropertiesSet(PortSetPair(PortSet(True), port_set_6), method_put)
        g = MultiLayerPropertiesSet()
        g.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_6)] = methods_get_put
        g.HTTP_allowed_requests_per_ports[PortSetPair(PortSet(True), port_set_7)] = method_get
        print(e)
        print(f)
        print(e|f)
        print(g)
        self.assertTrue(e|f == g)
        self.assertTrue(f | e == g)
        h = MultiLayerPropertiesSet(PortSetPair(PortSet(True), port_set_5))
        print(h | g)

    def test_subtract(self):
        port_set = PortSet()
        port_set.add_port_range(50, 60)
        port_set_2 = PortSet()
        port_set_2.add_port_range(40, 55)
        port_set_3 = PortSet()
        port_set_3.add_port_range(56, 70)
        port_set_4 = PortSet()
        port_set_4.add_port_range(57, 70)
        port_set_5 = PortSet()
        port_set_5.add_port(56)
        port_set_6 = PortSet()
        port_set_6.add_port_range(56, 60)
        port_set_7 = PortSet()
        port_set_7.add_port_range(50, 55)
        port_set_pair = PortSetPair(PortSet(True), port_set)
        method_get = RequestAttrs().add_methods({"GET"})
        methods_get_put = RequestAttrs().add_methods({"GET", "PUT"})
        method_put = RequestAttrs().add_methods({"PUT"})

        a = MultiLayerPropertiesSet(port_set_pair, method_get)
        print(a)
        print(a-a)
        c = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        print(c-a)
        print(a-c)
        print(c-c)












r'''

    def test_basic(self):
        empty_req_attr = RequestAttrs()
        method_get = empty_req_attr.add_methods({"GET"})
        port_set = PortSet()
        port_set.add_port(50)
        port_set.add_port(60)
        a = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)), method_get)
        b = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        c = MultiLayerPropertiesSet(PortSetPair(PortSet(True), port_set), method_get)
        d = MultiLayerPropertiesSet(PortSetPair(PortSet(True), port_set), RequestAttrs())
        e = MultiLayerPropertiesSet(PortSetPair(PortSet(True), port_set), RequestAttrs(True))
        print(a)
        print(b)
        print(c)
        print(d)
        print(e)
        self.assertTrue(True)

    def test_bool(self):
        a = MultiLayerPropertiesSet()
        self.assertFalse(bool(a))
        b = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)))
        self.assertTrue(bool(b))
        c = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)), RequestAttrs())
        self.assertTrue(bool(c))
        d = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)), RequestAttrs(True))
        self.assertTrue(bool(d))
'''
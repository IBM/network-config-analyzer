#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import itertools

from PortSet import PortSetPair, PortSet

"""
RequestAttrs  -  TODO:
1)  RequestAttrs.methods: For gRPC service, this will always be “POST”.

2) Add support for:
- request.host  => values extracted from policy fields at: to.operation.{hosts/notHosts} , 
- request.url_path => values extracted from policy fields at: to.operation.{paths/notPaths} ,
- request.auth.principal => values extracted from policy fields at from.source.{requestPrincipals/notRequestPrincipals} 
                                                                   when.key==request.auth.principal {values/notValues}
- request.headers         => values extracted from policy fields at when.key==request.headers {values/notValues}                                                                  
- request.auth.audiences  => values extracted from policy fields at when.key==request.auth.audiences {values/notValues}
- request.auth.audiences  => values extracted from policy fields at when.key==request.auth.audiences {values/notValues}
- request.auth.presenter  => values extracted from policy fields at when.key==request.auth.presenter {values/notValues}
- request.auth.claims     => values extracted from policy fields at when.key==request.auth.claims {values/notValues}


required semantic checks: 
--------------------------------
- request.url_path: For gRPC service, this will be the fully-qualified name in the form of “/package.service/method”.
- request.host: hosts should exist in the authorization policy namespace. 
                Kiali considers services and service entries. 
                Those hosts that refers to hosts outside of the object namespace will be presented with an unknown error
- request.auth.* : for keys with request.auth prefix: requires request authentication policy applied    
- request.headers: http headers from a list of options : https://en.wikipedia.org/wiki/List_of_HTTP_header_fields ,
                                                        https://www.w3.org/Protocols/HTTP/HTRQ_Headers.html

- request.methods: from https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
"""


class UnlimitedHttpAttributes:
    def __init__(self, allow_all=False):
        self.values = set()  # a set of unlimited strings
        self.negation = False  # True means !self.values
        self.allow_all = allow_all

    def __str__(self):
        if self.allow_all:
            return 'allows all'
        elif not self.values:
            return 'allows nothing'
        if not self.negation:
            res = ' in '
        else:
            res = ' not in '
        return f'{res}{self.values}'

    def copy(self):
        res = UnlimitedHttpAttributes()
        res.values = self.values.copy()
        res.negation = self.negation
        res.allow_all = self.allow_all
        return res

    def __bool__(self):
        return bool(self.values or self.allow_all)

    def __eq__(self, other):
        return self.values == other.values and \
               self.negation == other.negation and \
               self.allow_all == other.allow_all

    def __and__(self, other):
        res = UnlimitedHttpAttributes()
        if self.contained_in(other):
            res = self.copy()
            return res
        elif other.contained_in(self):
            res = other.copy()
            return res
        if not self.negation and not other.negation:
            res.values = set(self.values).intersection(other.values)
            # res.negation = False
        elif not self.negation and other.negation:
            res.values = set(self.values).difference(other.values)
            # res.negation = False
        elif self.negation and not other.negation:
            res.values = set(other.values).difference(self.values)
            # res.negation = False
        else:  # self.negation and other.negation
            res.values = set(self.values).union(other.values)
            res.negation = True
        return res

    def __or__(self, other):
        return self.__add__(other)

    def __add__(self, other):
        res = UnlimitedHttpAttributes()
        if self.allow_all or other.allow_all:
            res.allow_all = True
            return res
        if not self.negation and not other.negation:
            res.values = set(self.values).union(other.values)  # self.values + other.values
            # res.negation = False
        elif not self.negation and other.negation:
            res.values = set(other.values).difference(self.values)  # other.values - self.values
            res.negation = True
        elif self.negation and not other.negation:
            res.values = set(self.values).difference(other.values)  # self.values - other.values
            res.negation = True
        else:  # self.negation and other.negation
            res.values = set(self.values).intersection(other.values)  # self.values & other.values
            res.negation = True
        return res

    def __sub__(self, other):
        res = UnlimitedHttpAttributes()
        if not other.allow_all and not other.values:
            return self  # nothing to subtract
        if self.allow_all and other.allow_all:
            return res  # allow nothing
        elif self.allow_all:
            res.values = other.values
            res.negation = not other.negation
            return res
        elif other.allow_all:
            return res  # allow nothing
        if not self.negation and not other.negation:
            res.values = self.values - other.values
            # res.negation = False
        elif not self.negation and other.negation:
            res.values = self.values - (self.values - other.values)
            # res.negation = False
        elif self.negation and not other.negation:
            res.values = set(self.values).union(other.values)  # self.values + other.values
            res.negation = True
        else:  # self.negation and other.negation
            res.values = other.values - self.values
            # res.negation = False
        return res

    def __iand__(self, other):
        res = self.copy() & other
        self.values = res.values
        self.negation = res.negation
        self.allow_all = res.allow_all
        return self

    def __ior__(self, other):
        return self.__iadd__(other)

    def __iadd__(self, other):
        res = self.copy() + other
        self.values = res.values
        self.negation = res.negation
        self.allow_all = res.allow_all
        return self

    def __isub__(self, other):
        res = self.copy() - other
        self.values = res.values
        self.negation = res.negation
        self.allow_all = res.allow_all
        return self

    # shai - is this needed?
    '''
    def add_attributes(self, allow_all=False, attributes=None):
        assert (allow_all or attributes)
        other = UnlimitedHttpAttributes()
        if allow_all:
            self.values.clear()
            self.negation = False
            self.allow_all = True
        else:
            other.values = attributes
            self += other
    '''

    def contained_in(self, other):
        if other.allow_all or (not self.allow_all and not self.values):  # other allows all or self is empty
            return True
        if self.allow_all:  # and not other.allow_all
            return False
        # else, both list do not allow all values
        if not self.negation and not other.negation:
            return set(self.values).issubset(other.values)
        if not self.negation and other.negation:
            return set(self.values).isdisjoint(other.values)
        if self.negation and not other.negation:
            return False
        # else, self.negation and other.negation:
        return set(other.values).issubset(self.values)

    def set_attributes(self, attrs, not_attrs):
        assert (bool(attrs) != bool(not_attrs))  # xor - maybe switch to warning
        if attrs:
            self.values = attrs
            self.negation = False
            self.allow_all = False
        else:
            self.values = not_attrs
            self.negation = True
            self.allow_all = False


class RequestAttrs:
    http_methods = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'}

    def __init__(self, allow_all=False):
        self.methods = set()  # a set of strings for allowed request.method values
        if allow_all:
            self.methods |= RequestAttrs.http_methods
        # a set of UnlimitedHttpAttributes for allowed request.url_path values
        self.paths = UnlimitedHttpAttributes(allow_all)
        self.hosts = UnlimitedHttpAttributes(allow_all)

    def __bool__(self):
        return bool(self.methods) | \
               bool(self.paths) | \
               bool(self.hosts)

    def __eq__(self, other):
        if isinstance(other, RequestAttrs):
            res = self.methods == other.methods and \
                  self.paths == other.paths and \
                  self.hosts == other.hosts
            return res
        return NotImplemented

    def __str__(self):
        return f'request.method in {self.methods}\n' \
               f'request.url_path {self.paths}\n' \
               f'request.hosts {self.hosts}\n'

    def copy(self):
        res = RequestAttrs()
        res.methods = self.methods.copy()
        res.paths = self.paths.copy()
        res.hosts = self.hosts.copy()
        return res

    def __and__(self, other):
        res = RequestAttrs()
        res.methods = self.methods.intersection(other.methods)
        res.paths = self.paths & other.paths
        res.hosts = self.hosts & other.hosts
        return res

    def __or__(self, other):
        res = RequestAttrs()
        res.methods = self.methods.union(other.methods)
        res.paths = self.paths | other.paths
        res.hosts = self.hosts | other.hosts
        return res

    def __add__(self, other):
        return self.__or__(other)

    def __sub__(self, other):
        res = RequestAttrs()
        res.methods = self.methods.difference(other.methods)
        res.paths = self.paths - other.paths
        res.hosts = self.hosts - other.hosts
        return res

    def __iand__(self, other):
        self.methods.intersection_update(other.methods)
        self.paths &= other.paths
        self.hosts &= other.hosts
        return self

    def __ior__(self, other):
        self.methods.update(other.methods)
        self.paths |= other.paths
        self.hosts |= other.hosts
        return self

    def __iadd__(self, other):
        return self.__ior__(other)

    def __isub__(self, other):
        self.methods.difference_update(other.methods)
        self.paths -= other.paths
        self.hosts -= other.hosts
        return self

    def methods_contained_in(self, other):
        return self.methods.issubset(other.methods)

    def contained_in(self, other):
        return self.methods_contained_in(other) and \
               self.paths.contained_in(other.paths) and \
               self.hosts.contained_in(other.hosts)

    # shai - decide whether we need funcs add_methods, add_paths, remove_paths or only keep the set funcs
    def add_methods(self, methods):
        # TODO: what if methods is invalid?
        # shai - remove as it's pre-validated by callee
        assert methods.issubset(RequestAttrs.http_methods)
        self.methods |= methods
        return self

    def set_methods(self, methods):
        # shai - remove as it's pre-validated by callee
        assert methods.issubset(RequestAttrs.http_methods)
        self.methods = methods
        return self

    def add_paths(self, allow_all=False, attributes=None):
        if not allow_all and not attributes:
            return  # nothing to add
        other = UnlimitedHttpAttributes()
        other.allow_all = allow_all
        other.values = attributes
        self.paths.__iadd__(other)
        #self.add_unlimited_http_attributes(self.paths, allow_all, attributes)

    def remove_paths(self, disallow_all=False, not_attributes=None):
        if not disallow_all and not not_attributes:
            return  # nothing to remove
        other = UnlimitedHttpAttributes()
        if disallow_all:
            self.paths.__iand__(other)
        else:
            other.values = not_attributes
            self.paths.__isub__(other)
        #self.remove_unlimited_http_attributes(self.paths, disallow_all, not_attributes)

    def set_paths(self, paths_list, not_paths_list):
        self.paths.set_attributes(paths_list, not_paths_list)

    def set_hosts(self, hosts_list, not_hosts_list):
        self.hosts.set_attributes(hosts_list, not_hosts_list)

    # shai - remove two deprecated funcs below
    def add_unlimited_http_attributes(self, attributes_list, allow_all=False, attributes=None):
        assert (allow_all or attributes)
        if allow_all:
            attributes_list.values.clear()
            attributes_list.negation = False
            attributes_list.allow_all = True
            return
        if attributes_list.allow_all:
            return  # nothing to add
        if attributes_list.negation:
            if attributes.issubset(attributes_list.values):
                attributes_list.values.difference_update(attributes)
                if not attributes_list.values:  # new is empty -> allow all
                    attributes_list.negation = False
                    attributes_list.allow_all = True
            else:
                attributes_list.values = attributes
                attributes_list.negation = False
        else:  # !attributes_list.allow_all and !attributes_list.negation
            attributes_list.values |= attributes

    def remove_unlimited_http_attributes(self, attributes_list, disallow_all=False, not_attributes=None):
        assert (disallow_all or not_attributes)
        if disallow_all:
            attributes_list.values.clear()
            attributes_list.negation = False
            attributes_list.allow_all = False
            return
        if attributes_list.allow_all:
            attributes_list.values = not_attributes
            attributes_list.negation = True
            attributes_list.allow_all = False
        elif attributes_list.negation:
            attributes_list.values += not_attributes
        else:  # !attributes_list.allow_all and !attributes_list.negation
            attributes_list.values.difference_update(not_attributes)
            if not attributes_list.values:  # new is empty -> allow nothing
                attributes_list.negation = False
                attributes_list.allow_all = False

    # shai - need to enhance
    def get_first_item(self):
        if not self:
            return NotImplemented
        return list(self.methods)[0]

    # shai - need to enhance
    def print_diff(self, other, self_name, other_name):
        self_does_not = ' while ' + self_name + ' does not.'
        other_does_not = ' while ' + other_name + ' does not.'
        self_minus_other = self - other
        other_minus_self = other - self
        if self_minus_other:
            item = self_minus_other.get_first_item()
            return self_name + ' allows method ' + item + other_does_not
        if other_minus_self:
            item = other_minus_self.get_first_item()
            return other_name + ' allows method ' + item + self_does_not
        return 'No diff.'

    # def allow_all_requests(self):
    #    return self.methods == RequestAttrs.http_methods

    # TODO: fix ?
    def __hash__(self):
        return hash(frozenset(str(self)))


# TODO: this type object has to be in canonical form due to comparison operations..
# TODO: currently assuming that ports intervals in HTTP_allowed_requests_per_ports do not overlap
# in PortSetPair all requests are allowed implicitly, since they are not captured.
# in RequestSet we reason about ports (base class) + requests attributes.
# rename: multi-layer-properties-set
# TODO: add unit testing for MultiLayerPropertiesSet and RequestAttrs
# TODO: consider adding type with both as fields + requests_captured flag (to include operations on requests only if it is captured by at least one arg)
# a request type consists of 2 parts: (1) ports (2) request attributes
# deny port vs deny all requests is not the same ?
# if we allow port 50 with method GET only , do we also allow port 50 with plain TCP ? (http vs TCP)?
# https://istio.io/latest/docs/ops/common-problems/security-issues/#make-sure-you-are-not-using-http-only-fields-on-tcp-ports
# once using HTTP-only fields, it will deny plain TCP packets
class MultiLayerPropertiesSet:
    # mapping from allowed ports to their allowed request attributes
    def __init__(self, port_set=PortSetPair(PortSet(), PortSet()), request_attributes=None):
        self.HTTP_allowed_requests_per_ports = dict()
        # for every port with explicit HTTP-req attrs, plain TCP is not allowed
        self.plain_TCP_allowed_ports = PortSetPair(PortSet(), PortSet())
        if request_attributes is not None:  # ports have explicit HTTP req attr spec
            self.HTTP_allowed_requests_per_ports = {port_set: request_attributes} if port_set else {}
        else:
            self.plain_TCP_allowed_ports = port_set  # for every port here, all HTTP requests are also implicitly allowed

    def __bool__(self):
        return bool(self.plain_TCP_allowed_ports) or bool(self.HTTP_allowed_requests_per_ports)

    def __eq__(self, other):
        return self.plain_TCP_allowed_ports == other.plain_TCP_allowed_ports and \
               self.HTTP_allowed_requests_per_ports == other.HTTP_allowed_requests_per_ports

    def __str__(self):
        if not self.HTTP_allowed_requests_per_ports:
            return str(self.plain_TCP_allowed_ports)
        req_attrs_str = ''
        for key, val in self.HTTP_allowed_requests_per_ports.items():
            req_attrs_str += f'[{key}]=>[{val}]'
        return f'plain TCP allowed ports: {self.plain_TCP_allowed_ports} , HTTP allowed request attributes per ports: {req_attrs_str}'

    def _get_http_allowed_ports(self):
        res = PortSetPair()
        for key in self.HTTP_allowed_requests_per_ports.keys():
            res |= key
        return res

    def get_all_ports_for_certain_request_properties(self, request_attrs):
        res = self.plain_TCP_allowed_ports.copy()  # all possible request attrs are allowed by plain TCP
        for ports_interval, allowed_requests in self.HTTP_allowed_requests_per_ports.items():
            if request_attrs.contained_in(allowed_requests):
                res |= ports_interval
        return res

    # TODO: improve
    def contained_in(self, other):
        # case 1: self has allowed ports only for plain TCP
        if not self.HTTP_allowed_requests_per_ports:
            return self.plain_TCP_allowed_ports.contained_in(other.plain_TCP_allowed_ports)
        # case2 : other has allowed ports only for plain TCP
        if not other.HTTP_allowed_requests_per_ports:
            self_allowed_ports = self.plain_TCP_allowed_ports | self._get_http_allowed_ports()
            return self_allowed_ports.contained_in(other.plain_TCP_allowed_ports)
        # case 3: both self and other have ports with HTTP req attr
        # step 1- containment of self plain TCP ports in other plain TCP ports
        if not self.plain_TCP_allowed_ports.contained_in(other.plain_TCP_allowed_ports):
            return False
        # step 2- containment of self HTTP-req ports in other plain TCP + "containing" HTTP-req ports
        for ports_interval, allowed_requests in self.HTTP_allowed_requests_per_ports.items():
            other_ports_set_per_req_attr = other.get_all_ports_for_certain_request_properties(allowed_requests)
            if not ports_interval.contained_in(other_ports_set_per_req_attr):
                return False
        return True

    def copy(self):
        res = MultiLayerPropertiesSet()
        res.plain_TCP_allowed_ports = self.plain_TCP_allowed_ports.copy()
        for key, value in self.HTTP_allowed_requests_per_ports.items():
            key_copy = key.copy()
            val_copy = value.copy()
            res.HTTP_allowed_requests_per_ports[key_copy] = val_copy
        return res

    # shai - why static?
    @staticmethod
    def all_disjoint(portsets_input):
        for pair in itertools.permutations(portsets_input, 2):
            if pair[0] & pair[1]:
                return False
        return True

    def assert_disjoint_portsets(self):
        portsets_list = self.HTTP_allowed_requests_per_ports.keys()
        assert self.all_disjoint(portsets_list)

    def finalize_representation(self):
        self.assert_disjoint_portsets()
        new_dict = {}
        for port_set, req_attr in self.HTTP_allowed_requests_per_ports.items():
            if req_attr in new_dict:
                new_dict[req_attr] |= port_set
            else:
                new_dict[req_attr] = port_set
        self.HTTP_allowed_requests_per_ports = {}
        for req_attr, port_set in new_dict.items():
            self.HTTP_allowed_requests_per_ports[port_set] = req_attr
        self.assert_disjoint_portsets()

    # TODO: improve
    def __iand__(self, other):
        res = MultiLayerPropertiesSet()
        res.plain_TCP_allowed_ports = self.plain_TCP_allowed_ports & other.plain_TCP_allowed_ports
        a = self if self.HTTP_allowed_requests_per_ports else other
        b = other if a == self else self
        for ports_interval, allowed_requests in a.HTTP_allowed_requests_per_ports.items():
            remaining_ports_intervals = ports_interval.copy()
            if b.plain_TCP_allowed_ports & ports_interval:
                res.HTTP_allowed_requests_per_ports[b.plain_TCP_allowed_ports & ports_interval] = allowed_requests
                remaining_ports_intervals -= b.plain_TCP_allowed_ports & ports_interval
            if not remaining_ports_intervals:
                continue
            # for the remaining_ports_intervals => check the other HTTP_allowed_requests_per_ports
            for other_ports_interval, other_allowed_requests in b.HTTP_allowed_requests_per_ports.items():
                if remaining_ports_intervals & other_ports_interval:
                    res.HTTP_allowed_requests_per_ports[remaining_ports_intervals & other_ports_interval] = allowed_requests & other_allowed_requests
                    remaining_ports_intervals -= remaining_ports_intervals & other_ports_interval
                    if not remaining_ports_intervals:
                        break

        res.finalize_representation()
        self.HTTP_allowed_requests_per_ports = res.HTTP_allowed_requests_per_ports
        self.plain_TCP_allowed_ports = res.plain_TCP_allowed_ports
        return self

    def __and__(self, other):
        res = self.copy()
        res &= other
        return res

    # TODO: improve
    def __ior__(self, other):
        res = MultiLayerPropertiesSet()
        res.plain_TCP_allowed_ports = self.plain_TCP_allowed_ports | other.plain_TCP_allowed_ports
        temp_dict = {}  # relevant http-req from self
        for ports_interval, allowed_requests in self.HTTP_allowed_requests_per_ports.items():
            remaining_ports_intervals = ports_interval.copy() - res.plain_TCP_allowed_ports
            if remaining_ports_intervals:
                temp_dict[remaining_ports_intervals] = allowed_requests
        for ports_interval, allowed_requests in other.HTTP_allowed_requests_per_ports.items():
            remaining_ports_intervals = ports_interval.copy() - res.plain_TCP_allowed_ports
            # add remaining_ports_intervals w.r.t self:
            if not remaining_ports_intervals:
                continue
            for res_ports_interval, res_allowed_requests in temp_dict.items():
                if remaining_ports_intervals & res_ports_interval:
                    # split res_ports_interval
                    #del res.HTTP_allowed_requests_per_ports[res_ports_interval]
                    res.HTTP_allowed_requests_per_ports[remaining_ports_intervals & res_ports_interval] = res_allowed_requests | allowed_requests
                    #if res_ports_interval - remaining_ports_intervals & res_ports_interval:
                    #    res.HTTP_allowed_requests_per_ports[res_ports_interval - remaining_ports_intervals & res_ports_interval] = res_allowed_requests
                    #remaining_ports_intervals -= remaining_ports_intervals & res_ports_interval
                #else:
                #    res.HTTP_allowed_requests_per_ports[res_ports_interval] = res_allowed_requests
                if not remaining_ports_intervals:
                    break
        for ports_interval, allowed_requests in other.HTTP_allowed_requests_per_ports.items():
            remaining_ports_intervals = ports_interval.copy() - (res.plain_TCP_allowed_ports | res._get_http_allowed_ports())
            if remaining_ports_intervals:
                res.HTTP_allowed_requests_per_ports[remaining_ports_intervals] = allowed_requests
        for ports_interval, allowed_requests in self.HTTP_allowed_requests_per_ports.items():
            remaining_ports_intervals = ports_interval.copy() - (res.plain_TCP_allowed_ports | res._get_http_allowed_ports())
            if remaining_ports_intervals:
                res.HTTP_allowed_requests_per_ports[remaining_ports_intervals] = allowed_requests

        res.finalize_representation()
        self.HTTP_allowed_requests_per_ports = res.HTTP_allowed_requests_per_ports
        self.plain_TCP_allowed_ports = res.plain_TCP_allowed_ports
        return self

    def __or__(self, other):
        res = self.copy()
        res |= other
        return res

    # TODO: improve
    def __isub__(self, other):
        res = MultiLayerPropertiesSet()
        other_http_req_ports = other._get_http_allowed_ports()
        res.plain_TCP_allowed_ports = self.plain_TCP_allowed_ports - other.plain_TCP_allowed_ports - other_http_req_ports
        new_dict = {}
        if self.plain_TCP_allowed_ports & other_http_req_ports:
            for other_ports_interval, other_allowed_requests in other.HTTP_allowed_requests_per_ports.items():
                if self.plain_TCP_allowed_ports & other_ports_interval:
                    new_dict[self.plain_TCP_allowed_ports & other_ports_interval] = RequestAttrs(True) - other_allowed_requests

        for ports_interval, allowed_requests in self.HTTP_allowed_requests_per_ports.items():
            remaining_ports_interval = ports_interval.copy() - other.plain_TCP_allowed_ports
            if not remaining_ports_interval:
                continue

            if remaining_ports_interval - other_http_req_ports:
                new_dict[remaining_ports_interval - other_http_req_ports] = allowed_requests
            if remaining_ports_interval & other_http_req_ports: # subtract http_req required
                for other_ports_interval, other_allowed_requests in other.HTTP_allowed_requests_per_ports.items():
                    if remaining_ports_interval & other_ports_interval:
                        new_dict[remaining_ports_interval & other_ports_interval] = allowed_requests - other_allowed_requests

        res.HTTP_allowed_requests_per_ports = new_dict
        res.finalize_representation()
        self.HTTP_allowed_requests_per_ports = res.HTTP_allowed_requests_per_ports
        self.plain_TCP_allowed_ports = res.plain_TCP_allowed_ports
        return self

    def __sub__(self, other):
        res = self.copy()
        res -= other
        return res

    def print_diff(self, other, self_name, other_name):
        # TODO: fix this
        return self.plain_TCP_allowed_ports.print_diff(other.plain_TCP_allowed_ports, self_name, other_name)

    def has_named_ports(self):
        return self.plain_TCP_allowed_ports.has_named_ports()

    def get_named_ports(self):
        return self.plain_TCP_allowed_ports.get_named_ports()

    def convert_named_ports(self, named_ports, protocol):
        self.plain_TCP_allowed_ports.convert_named_ports(named_ports, protocol)

    def get_properties_obj(self):
        return self.plain_TCP_allowed_ports.get_properties_obj()


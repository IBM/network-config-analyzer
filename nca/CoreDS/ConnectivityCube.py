#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from .CanonicalIntervalSet import CanonicalIntervalSet
from .DimensionsManager import DimensionsManager
from .PortSet import PortSet
from .Peer import BasePeerSet
from .MinDFA import MinDFA


class ConnectivityCube(dict):
    """
    This class manages forth and back translations of all dimensions of ConnectivityProperties
     (translations between input format and internal format).
     It is used as an input interface for ConnectivityProperties methods.
    """

    all_dimensions_list = ["src_peers", "dst_peers", "protocols", "src_ports", "dst_ports", "methods", "hosts", "paths",
                           "icmp_type", "icmp_code"]

    def __init__(self, dimensions_list=None):
        """
        By default, each dimension in the cube is initialized with entire domain value, which represents
        "don't care" or inactive dimension (i.e., the dimension has no impact).
        """
        super().__init__()
        self.dimensions_list = dimensions_list if dimensions_list else self.all_dimensions_list
        self.named_ports = set()  # used only in the original solution
        self.excluded_named_ports = set()  # used only in the original solution
        dimensions_manager = DimensionsManager()
        for dim in self.dimensions_list:
            dim_value = dimensions_manager.get_dimension_domain_by_name(dim, True)
            self.set_dim_directly(dim, dim_value)

    def copy(self):
        """
        Returns a copy of the given ConnectivityCube object
        :rtype: ConnectivityCube
        """
        res = ConnectivityCube(self.dimensions_list)
        for dim_name, dim_value in self.items():
            if isinstance(dim_value, MinDFA):
                res.set_dim_directly(dim_name, dim_value)
            else:
                res.set_dim_directly(dim_name, dim_value.copy())
        return res

    def is_full_dim(self, dim_name):
        """
        Returns True iff a given dimension is full
        :param str dim_name: the given dimension name
        """
        return self.get_dim_directly(dim_name) == DimensionsManager().get_dimension_domain_by_name(dim_name)

    def is_active_dim(self, dim_name):
        """
        Returns True iff a given dimension is active (i.e., not full)
        :param str dim_name: the given dimension name
        """
        return not self.is_full_dim(dim_name)

    def set_dim_directly(self, dim_name, dim_value):
        """
        Sets a given dimension value directly, assuming the value is in the internal format of that dimension.
        :param str dim_name: the given dimension name
        :param dim_value: the given dimension value
        """
        assert dim_name in self.dimensions_list
        super().__setitem__(dim_name, dim_value)

    def get_dim_directly(self, dim_name):
        """
        Returns a given dimension value directly (in its internal format).
        :param str dim_name: the given dimension name
        """
        assert dim_name in self.dimensions_list
        return super().__getitem__(dim_name)

    def __setitem__(self, dim_name, dim_value):
        """
        Sets a given dimension value after converting it into the internal format of that dimension.
        :param str dim_name: the given dimension name
        :param dim_value: the given dimension value
        """
        assert dim_name in self.dimensions_list
        if dim_value is None:
            return
        if dim_name in ["src_peers", "dst_peers"]:
            # translate PeerSet to CanonicalIntervalSet
            self.set_dim_directly(dim_name, BasePeerSet().get_peer_interval_of(dim_value))
        elif dim_name in ["src_ports", "dst_ports"]:
            # extract port_set from PortSet
            self.set_dim_directly(dim_name, dim_value.port_set)
            if dim_name == "dst_ports":
                self.named_ports = dim_value.named_ports
                self.excluded_named_ports = dim_value.excluded_named_ports
        elif dim_name in ["icmp_type", "icmp_code"]:
            # translate int to CanonicalIntervalSet
            self.set_dim_directly(dim_name, CanonicalIntervalSet.get_interval_set(dim_value, dim_value))
        else:  # the rest of dimensions do not need a translation
            self.set_dim_directly(dim_name, dim_value)

    def update(self, the_dict=None, **f):
        """
        Sets multiple dimension values at once, after converting them into their internal formats.
        :param dict the_dict: a dictionary from dimension names to dimension values, having all dimensions to be set
        :param f: Not used; required by the base class (dict) interface.
        """
        for dim_name, dim_value in the_dict.items():
            self[dim_name] = dim_value

    def unset_dim(self, dim_name):
        """
        Sets a given dimension to its default (containing all possible values)
        :param str dim_name: the given dimension name
        """
        assert dim_name in self.dimensions_list
        dim_value = DimensionsManager().get_dimension_domain_by_name(dim_name, True)
        self.set_dim_directly(dim_name, dim_value)

    def unset_all_but_peers(self):
        for dim_name in self.dimensions_list:
            if dim_name not in ["src_peers", "dst_peers"]:
                self.unset_dim(dim_name)

    def __getitem__(self, dim_name):
        """
        Returns a given dimension value after converting it from internal to external format.
        :param str dim_name: the given dimension name
        """
        assert dim_name in self.dimensions_list
        dim_value = self.get_dim_directly(dim_name)
        if dim_name in ["src_peers", "dst_peers"]:
            if self.is_active_dim(dim_name):
                # translate CanonicalIntervalSet back to PeerSet
                return BasePeerSet().get_peer_set_by_indices(dim_value)
            else:
                return BasePeerSet().get_peer_set_by_indices(DimensionsManager().get_dimension_domain_by_name(dim_name))
        elif dim_name in ["src_ports", "dst_ports"]:
            res = PortSet()
            res.add_ports(dim_value)
            if dim_name == "dst_ports":
                res.named_ports = self.named_ports
                res.excluded_named_ports = self.excluded_named_ports
            return res
        elif dim_name in ["icmp_type", "icmp_code"]:
            if self.is_active_dim(dim_name):
                # translate CanonicalIntervalSet back to int
                return dim_value.validate_and_get_single_value()
            else:
                return None
        else:  # the rest of dimensions do not need a translation
            if isinstance(dim_value, MinDFA):
                return dim_value
            else:
                return dim_value.copy()   # TODO - do we need this copy?

    def has_active_dim(self):
        """
        Returns True iff the cube has at least one active dimension. Otherwise, returns False.
        """
        dimensions_manager = DimensionsManager()
        for dim in self.dimensions_list:
            if self.get_dim_directly(dim) != dimensions_manager.get_dimension_domain_by_name(dim):
                return True
        return False

    def is_empty(self):
        """
        Returns True iff the cube has at least one empty dimension. Otherwise, returns False.
        """
        dimensions_manger = DimensionsManager()
        for dim in self.dimensions_list:
            if self.get_dim_directly(dim) == dimensions_manger.get_empty_dimension_by_name(dim):
                # for "dst_ports" can have named ports in original solution
                if dim != "dst_ports" or (not self.named_ports and not self.excluded_named_ports):
                    return True
        return False

    def get_ordered_cube_and_active_dims(self):
        """
        Translate the connectivity cube to an ordered cube, and compute its active dimensions
        :return: tuple with: (1) cube values (2) active dimensions
        """
        cube = []
        active_dims = []
        dimensions_manager = DimensionsManager()
        # add values to cube by required order of dimensions
        for dim in self.dimensions_list:
            dim_value = self.get_dim_directly(dim)
            if dim_value != dimensions_manager.get_dimension_domain_by_name(dim):
                if isinstance(dim_value, MinDFA):
                    cube.append(dim_value)
                else:
                    cube.append(dim_value.copy())  # TODO - do we need this copy?
                active_dims.append(dim)
        return cube, active_dims

    @staticmethod
    def make_from_dict(the_dict):
        ccube = ConnectivityCube()
        ccube.update(the_dict)
        return ccube

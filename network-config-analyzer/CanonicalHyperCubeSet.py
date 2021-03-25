#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet


class CanonicalHyperCubeSet:
    def __init__(self, n):
        self.layers = []  # array of mappings (tuples) from ranges (intervals) to CanonicalHyperCubeSet(n-1)
        self.dimensions = n
        self.baseIntervalSet = CanonicalIntervalSet()

    def __bool__(self):
        # type: (CanonicalHyperCubeSet) -> bool
        if self.dimensions > 1:
            return bool(self.layers)
        return bool(self.baseIntervalSet)

    def __eq__(self, other):
        # type: (CanonicalHyperCubeSet) -> bool
        if isinstance(other, CanonicalHyperCubeSet):
            if self.dimensions != other.dimensions:
                return False
            if self.dimensions == 1:
                return self.baseIntervalSet == other.baseIntervalSet
            return self.layers == other.layers
        return False

    def __len__(self):
        if self.dimensions == 1:
            return len(self.baseIntervalSet)
        return len(self.layers)

    def __hash__(self):
        if self.dimensions == 1:
            return hash(self.baseIntervalSet)
        return hash(frozenset(self.layers))

    def __iter__(self):
        if self.dimensions == 1:
            return iter(self.baseIntervalSet)
        return iter(self.layers)

    def __str__(self):
        # type: (CanonicalHyperCubeSet) -> str
        res = ""
        if self.dimensions == 1:
            res = str(self.baseIntervalSet)
        else:
            if not self.layers:
                return "Empty"
            for elem in self.layers:
                res += str(elem[0]) + ' => ' + '[' + str(elem[1]) + ']' + ';'
        return res

    def copy(self):
        # type: () -> CanonicalHyperCubeSet
        res = CanonicalHyperCubeSet(self.dimensions)
        for layer in self.layers:
            res.layers.append((layer[0].copy(), layer[1].copy()))
        res.baseIntervalSet = self.baseIntervalSet.copy()
        return res

    # item is a list of size matching the dimensions
    def __contains__(self, item):
        if self.dimensions == 1:
            return item[0] in self.baseIntervalSet
        for layer in self.layers:
            if item[0] in layer[0]:
                return item[1:] in layer[1]
        return False

    def __and__(self, other):
        # type: (CanonicalHyperCubeSet) -> CanonicalHyperCubeSet
        res = self.copy()
        res &= other
        return res

    def __iand__(self, other):
        # type: (CanonicalHyperCubeSet) -> CanonicalHyperCubeSet
        if self.dimensions == 1:
            self.baseIntervalSet = self.baseIntervalSet & other.baseIntervalSet
            return self
        res_layers = []
        for self_layer in self.layers:
            for other_layer in other.layers:
                common_intervals = self_layer[0] & other_layer[0]
                if len(common_intervals) == 0:
                    common_interval = []
                    new_sub_elem = None
                else:
                    common_interval = common_intervals[0]
                    new_sub_elem = self_layer[1] & other_layer[1]
                if common_interval and new_sub_elem:
                    res_layers.append((common_interval, new_sub_elem))
        self.layers = res_layers
        return self

    def get_list_of_all_intervals_paths(self):
        res = []
        if self.dimensions == 1:
            for interval in self.baseIntervalSet:
                res.append([interval])
            return res

        for layer in self.layers:
            layer_interval = layer[0]
            sub_res = layer[1].get_list_of_all_intervals_paths()
            for sub_arr in sub_res:
                res.append(([layer_interval] + sub_arr))
        return res

    def __or__(self, other):
        # type: (CanonicalHyperCubeSet) -> CanonicalHyperCubeSet
        res = self.copy()
        res |= other
        return res

    def __ior__(self, other):
        # type: (CanonicalHyperCubeSet) -> CanonicalHyperCubeSet
        intervals_list = other.get_list_of_all_intervals_paths()
        for interval in intervals_list:
            self.add_interval(interval)
        return self

    def __sub__(self, other):
        # type: (CanonicalHyperCubeSet) -> CanonicalHyperCubeSet
        res = self.copy()
        res -= other
        return res

    def __isub__(self, other):
        # type: (CanonicalHyperCubeSet) -> CanonicalHyperCubeSet
        intervals_list = other.get_list_of_all_intervals_paths()
        for interval in intervals_list:
            self.add_hole(interval)
        return self

    def clear(self):
        self.baseIntervalSet = CanonicalIntervalSet()
        self.layers = []

    def contained_in(self, other):
        # type: (CanonicalHyperCubeSet) -> bool
        if self.dimensions == 1:
            return self.baseIntervalSet.contained_in(other.baseIntervalSet)
        is_subset_count = 0
        for layer in self.layers:
            current_layer_0 = layer[0].copy()
            for other_layer in other.layers:
                other_interval = other_layer[0]
                other_sub_elem = other_layer[1]
                common_part = current_layer_0 & other_interval
                if len(common_part) == 1:
                    layers_remaining = current_layer_0 - common_part[0]
                else:
                    layers_remaining = [current_layer_0]
                flag = len(layers_remaining) == 0 or (
                        len(layers_remaining) == 1 and layers_remaining[0] > other_interval)
                # if layer[0].is_subset(other_interval):
                if len(common_part) == 1 and flag:
                    if not layer[1].contained_in(other_sub_elem):
                        return False

                    if len(layers_remaining) == 1:
                        current_layer_0 = layers_remaining[0]
                    else:
                        is_subset_count += 1
                        break
        return is_subset_count == len(self.layers)

    def overlaps(self, other):
        # type: (CanonicalHyperCubeSet) -> bool
        if self.dimensions == 1:
            return self.baseIntervalSet.overlaps(other.baseIntervalSet)
        for other_layer in other.layers:
            other_interval = other_layer[0]
            other_sub_elem = other_layer[1]
            for layer in self.layers:
                if layer[0].overlaps(other_interval):
                    if layer[1].overlaps(other_sub_elem):
                        return True
        return False

    #  interval_to_add is an array of intervals as the size of the dimensions
    #  each interval is of type CanonicalIntervalSet.Interval
    def add_interval(self, interval_to_add):
        # type: (list) -> None
        new_interval = interval_to_add[0].copy()
        # print(new_interval)
        if self.dimensions == 1:
            self.baseIntervalSet.add_interval(new_interval)
        else:
            new_sub_element = CanonicalHyperCubeSet(
                self.dimensions - 1)  # only needed if new_interval is not contained in an existing interval
            new_sub_element.add_interval(interval_to_add[1:])
            new_layers = []
            new_interval_added = False
            for layer in self.layers:
                layer_interval = layer[0]
                layer_sub_element = layer[1]
                # case : no overlapping, new interval added first
                if not new_interval_added and new_interval.end < layer_interval.start:
                    new_layers.append((new_interval, new_sub_element))
                    new_interval_added = True
                    new_layers.append(layer)
                # case  : orig,common,orig
                elif not new_interval_added and new_interval.is_subset(layer_interval):
                    interval_original_parts = layer_interval - new_interval
                    interval_new_part = new_interval
                    if len(interval_original_parts) >= 1 and interval_original_parts[0] < interval_new_part:
                        new_layers.append((interval_original_parts[0], layer_sub_element.copy()))
                    new_combined_layer = (layer_sub_element.copy())
                    new_combined_layer.add_interval(interval_to_add[1:])
                    new_layers.append((interval_new_part, new_combined_layer))
                    for interval_part in interval_original_parts:
                        if interval_new_part < interval_part:
                            new_layers.append((interval_part, layer_sub_element.copy()))
                    new_interval_added = True
                elif not new_interval_added and (new_interval.overlaps(layer_interval)):
                    orig_interval_parts = layer_interval - new_interval
                    new_interval_parts = new_interval - layer_interval
                    common_parts = layer_interval & new_interval
                    # case : new,common,orig
                    if (len(orig_interval_parts) > 0 and orig_interval_parts[0] > common_parts[0]) or (
                            len(orig_interval_parts) == 0 and len(new_interval_parts) == 1 and new_interval_parts[0] <
                            common_parts[0]):
                        if len(new_interval_parts) > 0:
                            new_part = new_interval_parts[0]
                            new_layers.append((new_part, new_sub_element))
                        new_common_part = common_parts[0]
                        new_combined_layer = (layer_sub_element.copy())
                        new_combined_layer.add_interval(interval_to_add[1:])
                        new_layers.append((new_common_part, new_combined_layer))
                        if len(orig_interval_parts) > 0:
                            orig_part = orig_interval_parts[0]
                            new_layers.append((orig_part, layer_sub_element))
                        new_interval_added = True

                    # case : orig,common,new
                    elif len(new_interval_parts) > 0 and new_interval_parts[0] > common_parts[0]:
                        if len(orig_interval_parts) > 0:
                            orig_part = orig_interval_parts[0]
                            new_layers.append((orig_part, layer_sub_element))
                        new_common_part = common_parts[0]
                        new_combined_layer = (layer_sub_element.copy())
                        new_combined_layer.add_interval(interval_to_add[1:])
                        new_layers.append((new_common_part, new_combined_layer))
                        new_interval = new_interval_parts[0]  # continue exploring the remaining new interval

                    # case : new,common,new
                    elif len(new_interval_parts) > 1 and new_interval_parts[1] > common_parts[0]:
                        new_part = new_interval_parts[0]
                        new_layers.append((new_part, new_sub_element))
                        new_common_part = common_parts[0]
                        new_combined_layer = (layer_sub_element.copy())
                        new_combined_layer.add_interval(interval_to_add[1:])
                        new_layers.append((new_common_part, new_combined_layer))
                        new_interval = new_interval_parts[1]  # continue exploring the remaining new interval

                else:
                    new_layers.append(layer)

            if not new_interval_added:
                new_layers.append((new_interval, new_sub_element))
            self.layers = new_layers
            self.apply_intervals_union()

    def add_hole(self, hole):
        # type: (list) -> None
        # hole is an array of intervals as the size of the dimensions
        # each interval is of type CanonicalIntervalSet.Interval

        if self.dimensions == 1:
            self.baseIntervalSet.add_hole(hole[0])
            return
        new_layers = []
        hole_interval = hole[0]
        for layer in self.layers:
            layer_interval = layer[0]
            layer_sub_elem = layer[1]

            if hole_interval.is_subset(layer_interval):
                intervals_to_add_orig = layer_interval - hole_interval
                interval_to_add_hole = hole_interval
                if len(intervals_to_add_orig) > 0 and intervals_to_add_orig[0] < interval_to_add_hole:
                    layer_to_add = (intervals_to_add_orig[0], layer_sub_elem)
                    new_layers.append(layer_to_add)
                new_sub_elem = layer_sub_elem.copy()
                new_sub_elem.add_hole(hole[1:])
                if new_sub_elem:  # not empty
                    layer_to_add = (hole_interval, new_sub_elem)
                    new_layers.append(layer_to_add)
                if len(intervals_to_add_orig) > 1 and intervals_to_add_orig[1] > interval_to_add_hole:
                    layer_to_add = (intervals_to_add_orig[1], layer_sub_elem)
                    new_layers.append(layer_to_add)
                elif len(intervals_to_add_orig) > 0 and intervals_to_add_orig[0] > interval_to_add_hole:
                    layer_to_add = (intervals_to_add_orig[0], layer_sub_elem)
                    new_layers.append(layer_to_add)

            elif hole_interval.overlaps(layer_interval):
                orig_interval_parts = layer_interval - hole_interval
                hole_interval_parts = hole_interval - layer_interval
                common_parts = layer_interval & hole_interval

                if (len(orig_interval_parts) > 0 and orig_interval_parts[0] > common_parts[0]) or (
                        len(orig_interval_parts) == 0 and len(hole_interval_parts) == 1 and hole_interval_parts[0] <
                        common_parts[0]):
                    new_common_part = common_parts[0]
                    new_combined_layer = (layer_sub_elem.copy())
                    new_combined_layer.add_hole(hole[1:])
                    if new_combined_layer:  # not empty
                        new_layers.append((new_common_part, new_combined_layer))
                    if len(orig_interval_parts) > 0:
                        orig_part = orig_interval_parts[0]
                        new_layers.append((orig_part, layer_sub_elem))

                elif len(hole_interval_parts) > 0 and hole_interval_parts[0] > common_parts[0]:
                    if len(orig_interval_parts) > 0:
                        orig_part = orig_interval_parts[0]
                        new_layers.append((orig_part, layer_sub_elem))
                    new_common_part = common_parts[0]
                    new_combined_layer = (layer_sub_elem.copy())
                    new_combined_layer.add_hole(hole[1:])
                    if new_combined_layer:  # not empty
                        new_layers.append((new_common_part, new_combined_layer))
                    hole_interval = hole_interval_parts[0]  # continue exploring the remaining hole interval with next
                    # existing intervals

                elif len(hole_interval_parts) > 1 and hole_interval_parts[1] > common_parts[0]:
                    new_common_part = common_parts[0]
                    new_combined_layer = (layer_sub_elem.copy())
                    new_combined_layer.add_hole(hole[1:])
                    if new_combined_layer:  # not empty
                        new_layers.append((new_common_part, new_combined_layer))
                    hole_interval = hole_interval_parts[1]  # continue exploring the remaining hole interval with next

            else:
                new_layers.append(layer)

        self.layers = new_layers
        self.apply_intervals_union()

    def apply_intervals_union(self):
        if self.dimensions <= 1:
            return
        if len(self.layers) == 0:
            return
        new_layers = []
        prev_layer = []
        for layer in self.layers:
            layer[1].apply_intervals_union()
            if prev_layer and (prev_layer[0].touches(layer[0])) and layer[1] == prev_layer[1]:
                layer = ((prev_layer[0] | layer[0])[0], layer[1])
            elif prev_layer:
                new_layers.append(prev_layer)
            prev_layer = layer
        new_layers.append(prev_layer)
        self.layers = new_layers

    def get_first_item(self):
        if not self:
            return NotImplemented
        if self.dimensions == 1:
            return [self.baseIntervalSet.rep()]
        return [self.layers[0][0].start] + self.layers[0][1].get_first_item()

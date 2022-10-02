from CanonicalHyperCubeSet import CanonicalHyperCubeSet


def track(func_name: str, *args, result=None):
    # TODO: implement
    print(f'operation={func_name}')
    print(f'args={args}')
    if result is not None:
        print(f'result={result}')


class CanonicalHyperCubeSetTracker:
    """Note: I have to manually copy the code since dynamically overriding magic functions (e.g. __eq__) does not
    work correctly."""
    def __getattr__(self, attr):
        return getattr(self.hyper_cube_set, attr)

    def __init__(self, dimensions=None, allow_all=False, hyper_cube_set: CanonicalHyperCubeSet = None):
        if hyper_cube_set is None:
            track('__init__', self, dimensions, allow_all)
            self.hyper_cube_set = CanonicalHyperCubeSet(dimensions, allow_all)
        else:
            self.hyper_cube_set = hyper_cube_set

    @staticmethod
    def create_from_cube(all_dims, cube, cube_dims):
        result = CanonicalHyperCubeSet.create_from_cube(all_dims, cube, cube_dims)
        track('create_from_cube', all_dims, cube, cube_dims, result=result)
        return CanonicalHyperCubeSetTracker(hyper_cube_set=result)

    def __bool__(self):
        result = self.hyper_cube_set.__bool__()
        track('__bool__', self, result=result)
        return result

    def __eq__(self, other):
        result = self.hyper_cube_set.__eq__(other)
        track('__eq__', self, other, result=result)
        return result

    def copy(self):
        result = self.hyper_cube_set.copy()
        track('copy', self, result=result)
        return result

    def __contains__(self, item):
        result = self.hyper_cube_set.__contains__(item)
        track('__contains__', self, item, result=result)
        return result

    def __and__(self, other):
        result = self.hyper_cube_set.__and__(other)
        track('__and__', self, other, result=result)
        return result

    def __iand__(self, other):
        result = self.hyper_cube_set.__iand__(other)
        track('__iand__', self, other, result=result)
        return result

    def __or__(self, other):
        result = self.hyper_cube_set.__or__(other)
        track('__or__', self, other, result=result)
        return result

    def __ior__(self, other):
        result = self.hyper_cube_set.__ior__(other)
        track('__ior__', self, other, result=result)
        return result

    def __sub__(self, other):
        result = self.hyper_cube_set.__sub__(other)
        track('__sub__', self, other, result=result)
        return result

    def __isub__(self, other):
        result = self.hyper_cube_set.__isub__(other)
        track('__isub__', self, other, result=result)
        return result

    def is_all(self):
        result = self.hyper_cube_set.is_all()
        track('is_all', self, result=result)
        return result

    def set_all(self):
        self.hyper_cube_set.set_all()
        track('set_all', self)

    def contained_in(self, other):
        result = self.hyper_cube_set.contained_in(other)
        track('contained_in', self, other, result=result)
        return result

    def clear(self):
        self.hyper_cube_set.clear()
        track('clear', self)

    def add_cube(self, cube_to_add, cube_dimensions=None):
        self.hyper_cube_set.add_cube(cube_to_add, cube_dimensions)
        track('add_cube', self, cube_to_add, cube_dimensions)

    def add_hole(self, hole_to_add, hole_dimensions=None):
        self.hyper_cube_set.add_hole(hole_to_add, hole_dimensions)
        track('add_hole', self, hole_to_add, hole_dimensions)


def _example():
    from DimensionsManager import DimensionsManager
    from MinDFA import MinDFA
    from CanonicalIntervalSet import CanonicalIntervalSet

    dimensions = ["src_ports", "ports", "methods_dfa", "paths"]
    dim_manager = DimensionsManager()
    dim_manager.set_domain("methods_dfa", DimensionsManager.DimensionType.DFA)
    dim_manager.set_domain("ports", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("x", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("y", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("z", DimensionsManager.DimensionType.IntervalSet, (1, 65535))

    s = CanonicalHyperCubeSetTracker.create_from_cube(dimensions, [MinDFA.dfa_from_regex("PUT")], ["methods_dfa"])

    ports_range = CanonicalIntervalSet.get_interval_set(100, 200)
    methods_dfa = MinDFA.dfa_from_regex("PUT")
    cube2 = [ports_range, methods_dfa]
    x = CanonicalHyperCubeSetTracker.create_from_cube(dimensions, cube2, ["ports", "methods_dfa"])
    if x == s:
        print('True')
    else:
        print('False')


if __name__ == '__main__':
    _example()

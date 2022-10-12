import json

from smt_experiments.canonical_hyper_cube_set_tracker.CanonicalHyperCubeSetOriginal import CanonicalHyperCubeSetOriginal
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.MinDFA import MinDFA
from smt_experiments.canonical_hyper_cube_set_tracker.trace_logger import get_trace_logger


def process_interval_set(interval_set: CanonicalIntervalSet) -> list[list[int]]:
    return [[i.start, i.end] for i in interval_set.interval_set]


def process_min_dfa(min_dfa: MinDFA):
    return min_dfa.creation_tree.serialize()


TRACE_LOGGER = get_trace_logger()


def process_args(args):
    if args is None:
        return args

    if isinstance(args, (bool, int, str)):
        return args

    if isinstance(args, (list, tuple)):
        return [process_args(arg) for arg in args]

    if isinstance(args, CanonicalHyperCubeSet):
        return {
            'type': 'CanonicalHyperCubeSet',
            'id': id(args.hyper_cube_set)
        }

    if isinstance(args, CanonicalHyperCubeSetOriginal):
        return {
            'type': 'CanonicalHyperCubeSet',
            'id': id(args)
        }

    if isinstance(args, CanonicalIntervalSet):
        return {
            'type': 'CanonicalIntervalSet',
            'intervals': process_interval_set(args)
        }

    if isinstance(args, MinDFA):
        return {
            'type': 'MinDFA',
            'regex': process_min_dfa(args)
        }

    raise TypeError(f'type {type(args)} is not supported.')


# TODO: create a trace that I can run and show to Adi
# TODO: I can augment the traces by permuting the order of operations, does it make sense? or by
#   mutating them in some ways


def track(func_name: str, *args, result=None):
    record = {
        'operation_name': func_name,
        'args': process_args(args),
        'result': process_args(result)
    }
    record_str = json.dumps(record)
    TRACE_LOGGER.info(record_str)


class CanonicalHyperCubeSet:
    """Note: I have to manually copy the code since dynamically overriding magic functions (e.g. __eq__) does not
    work correctly."""

    # def __getattr__(self, attr):
    #     # print(f'Hi, {attr}')
    #     # curframe = inspect.currentframe()
    #     # calframe = inspect.getouterframes(curframe, 2)
    #     # caller_frame = calframe[1]
    #     # print(f'file={caller_frame.filename}, function={caller_frame.function}')
    #     return getattr(self.hyper_cube_set, attr)

    @staticmethod
    def _copy_layer_elem(elem):
        return CanonicalHyperCubeSetOriginal._copy_layer_elem(elem)

    @property
    def layers(self):
        return self.hyper_cube_set.layers

    @layers.setter
    def layers(self, value):
        self.hyper_cube_set.layers = value

    @property
    def active_dimensions(self):
        return self.hyper_cube_set.active_dimensions

    @active_dimensions.setter
    def active_dimensions(self, value):
        self.hyper_cube_set.active_dimensions = value

    def __len__(self):
        return len(self.hyper_cube_set)

    def __hash__(self):
        return hash(self.hyper_cube_set)

    def __iter__(self):
        return iter(self.hyper_cube_set)

    empty_interval = CanonicalIntervalSet()

    def __init__(self, dimensions=None, allow_all=False, hyper_cube_set: CanonicalHyperCubeSetOriginal = None):
        if hyper_cube_set is None:
            self.hyper_cube_set = CanonicalHyperCubeSetOriginal(dimensions, allow_all)
            track('__init__', self, dimensions, allow_all)
        else:
            self.hyper_cube_set = hyper_cube_set

        if isinstance(self.hyper_cube_set, CanonicalHyperCubeSet):
            raise RuntimeError('got hyper cube set tracker')

    @staticmethod
    def create_from_cube(all_dims, cube, cube_dims):
        result = CanonicalHyperCubeSetOriginal.create_from_cube(all_dims, cube, cube_dims)
        result = CanonicalHyperCubeSet(hyper_cube_set=result)
        track('create_from_cube', all_dims, cube, cube_dims, result=result)
        return result

    def __bool__(self):
        result = self.hyper_cube_set.__bool__()
        track('__bool__', self, result=result)
        return result

    def __eq__(self, other):
        result = self.hyper_cube_set.__eq__(other.hyper_cube_set)
        track('__eq__', self, other, result=result)
        return result

    def copy(self):
        result = self.hyper_cube_set.copy()
        result = CanonicalHyperCubeSet(hyper_cube_set=result)
        track('copy', self, result=result)
        return result

    def __contains__(self, item):
        result = self.hyper_cube_set.__contains__(item)
        track('__contains__', self, item, result=result)
        return result

    def __and__(self, other):
        result = self.hyper_cube_set.__and__(other.hyper_cube_set)
        result = CanonicalHyperCubeSet(hyper_cube_set=result)
        track('__and__', self, other, result=result)
        return result

    def __iand__(self, other):
        result = self.hyper_cube_set.__iand__(other.hyper_cube_set)
        track('__iand__', self, other, result=result)
        return self

    def __or__(self, other):
        result = self.hyper_cube_set.__or__(other.hyper_cube_set)
        result = CanonicalHyperCubeSet(hyper_cube_set=result)
        track('__or__', self, other, result=result)
        return result

    def __ior__(self, other):
        result = self.hyper_cube_set.__ior__(other.hyper_cube_set)
        track('__ior__', self, other, result=result)
        return self

    def __sub__(self, other):
        result = self.hyper_cube_set.__sub__(other.hyper_cube_set)
        result = CanonicalHyperCubeSet(hyper_cube_set=result)
        track('__sub__', self, other, result=result)
        return result

    def __isub__(self, other):
        result = self.hyper_cube_set.__isub__(other.hyper_cube_set)
        track('__isub__', self, other, result=result)
        return self

    def is_all(self):
        result = self.hyper_cube_set.is_all()
        track('is_all', self, result=result)
        return result

    def set_all(self):
        self.hyper_cube_set.set_all()
        track('set_all', self)

    def contained_in(self, other):
        result = self.hyper_cube_set.contained_in(other.hyper_cube_set)
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
    from nca.CoreDS.DimensionsManager import DimensionsManager

    dimensions = ["src_ports", "ports", "methods_dfa", "paths"]
    dim_manager = DimensionsManager()
    dim_manager.set_domain("methods_dfa", DimensionsManager.DimensionType.DFA)
    dim_manager.set_domain("ports", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("x", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("y", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
    dim_manager.set_domain("z", DimensionsManager.DimensionType.IntervalSet, (1, 65535))

    s = CanonicalHyperCubeSet.create_from_cube(dimensions, [MinDFA.dfa_from_regex("PUT")], ["methods_dfa"])

    ports_range = CanonicalIntervalSet.get_interval_set(100, 200)
    methods_dfa = MinDFA.dfa_from_regex("PUT")
    cube2 = [ports_range, methods_dfa]
    x = CanonicalHyperCubeSet.create_from_cube(dimensions, cube2, ["ports", "methods_dfa"])
    if x == s:
        print('True')
    else:
        print('False')


if __name__ == '__main__':
    _example()

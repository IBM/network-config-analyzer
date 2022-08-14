import sys
from types import FrameType
from typing import Type, Any

from CanonicalIntervalSet import CanonicalIntervalSet


# TODO:
#   - change this class so it can take any method / function
class FunctionTracker:
    def __init__(self, func_name: str, to_track: list[str], belongs_to_class: Type = None, source_file: str = None):
        """TODO: write docs

        :param func_name: the name of the function to track
        :param to_track: name of stats to track and a callback that calculates them from the locals()
        :param belongs_to_class: if there are different methods with the same name, this will be used in order to
            select the correct function
        :param source_file: if there are different functions with the same name, this will be used to determine the
            correct one
        """
        # TODO: implement
        # TODO: this class will not activate the `settrace`, this is only a single hook. the `settrace` will use a
        #  function that calls a list of FunctionTracker
        pass


class IntervalSizeContainedInHook:
    def __init__(self):
        self.record = {'n_intervals_self': [],
                       'n_intervals_other': []}
        sys.settrace(self.hook)

    def hook(self, frame: FrameType, event: str, arg: Any):
        if frame.f_code.co_name == 'contained_in':
            called_self = frame.f_locals['self']
            if isinstance(called_self, CanonicalIntervalSet):
                called_other: CanonicalIntervalSet = frame.f_locals['other']
                self.record['n_intervals_self'].append(len(called_self))
                self.record['n_intervals_other'].append(len(called_other))

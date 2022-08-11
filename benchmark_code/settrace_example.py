import sys
from types import FrameType
from typing import Any

from CanonicalIntervalSet import CanonicalIntervalSet


def call_tracer(frame: FrameType, event: str, arg: Any):
    # called for every new scope, event = 'call', arg = None
    # frame is a frame object, not a function!
    # print(f"Entering: {frame.f_code.co_name}")
    # print(
    #     f'func_name={frame.f_code.co_name}, '
    #     # f'{frame.f_code.co_names}, '
    #     # f'{frame.f_code.co_code}, '
    #     # f'{frame.f_code.co_freevars}, '
    #     f'{frame.f_code.co_varnames}, '
    #     f'{frame.f_code.co_cellvars}, '
    #     f'{frame.f_code.co_filename}, '
    #     # f'event={event}, '
    #     # f'arg={arg}'
    # )
    if frame.f_code.co_name == 'contained_in':
        if isinstance(frame.f_locals['self'], CanonicalIntervalSet):
            print(len(frame.f_locals['self'].interval_set), len(frame.f_locals['other'].interval_set))
    return None


def audit_func(event, args):
    print(f'event={event}, args={args}')


def func1(x: int, y: str) -> str:
    return y * x


def func2(y: str) -> str:
    return func1(3, y)


def func3() -> str:
    return func2("banana")


if __name__ == "__main__":
    sys.settrace(call_tracer)
    # sys.addaudithook(audit_func)
    # func3()
    x = CanonicalIntervalSet()
    y = CanonicalIntervalSet()
    x.contained_in(y)

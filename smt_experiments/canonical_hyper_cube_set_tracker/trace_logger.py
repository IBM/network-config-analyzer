import logging

from smt_experiments.canonical_hyper_cube_set_tracker.utils import get_traces_dir


def get_trace_logger():
    return logging.getLogger('trace_logger')


def init_benchmark_tracing(benchmark_name: str):
    # TODO: if I want to add timing I can do that in here. by adding a formatter.

    logger = get_trace_logger()
    logger.setLevel(logging.INFO)

    if len(logger.handlers) > 0:
        assert len(logger.handlers) == 1
        handler = logger.handlers[0]
        logger.removeHandler(handler)

    file = get_traces_dir() / (benchmark_name + '.txt')
    handler = logging.FileHandler(file, 'w')
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)


def example():
    logger = get_trace_logger()
    init_benchmark_tracing('a')
    logger.info('1')
    init_benchmark_tracing('b')
    logger.info('2')
    init_benchmark_tracing('c')
    logger.info('3')


if __name__ == '__main__':
    example()

from collections import defaultdict


class RuntimeParamLogger:
    def __init__(self):
        self._records = defaultdict(list)
        self._is_recording = False

    def is_recording(self) -> bool:
        return self._is_recording

    def record(self, data: dict):
        if not self.is_recording():
            raise RuntimeError('cannot record when recording is not enabled')
        for key, value in data.items():
            self._records[key].append(value)

    def get_records(self) -> dict:
        return self._records

    def __enter__(self):
        self._records = defaultdict(list)
        self._is_recording = True

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._is_recording = False


global_runtime_param_logger = RuntimeParamLogger()


def _example_aux(runtime_param_logger: RuntimeParamLogger, data: dict):
    if runtime_param_logger.is_recording():
        runtime_param_logger.record(data)


def _example():
    runtime_param_logger = RuntimeParamLogger()
    print(f'recording: {runtime_param_logger.is_recording()}')
    with runtime_param_logger:
        print(f'recording: {runtime_param_logger.is_recording()}')
        _example_aux(runtime_param_logger, {'bla': 4, 'blabla': 'funfun'})
        _example_aux(runtime_param_logger, {'bla': 'kk', 'ma': 1})

    print(f'recording: {runtime_param_logger.is_recording()}')
    print(f'records: {runtime_param_logger.get_records()}')


if __name__ == '__main__':
    _example()

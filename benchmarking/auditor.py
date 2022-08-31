# TODO: place here all the logging stuff, auditing.py and logging in the code should be done using the
#   given interface
import io
import json
import logging
from pathlib import Path


class Auditor:
    _audit_logger = logging.getLogger('audit_logger')
    _audit_logger.setLevel(logging.ERROR)

    @staticmethod
    def is_enabled() -> bool:
        return Auditor._audit_logger.isEnabledFor(logging.INFO)

    @staticmethod
    def log_dict(data: dict) -> None:
        Auditor._audit_logger.info(json.dumps(data))

    def __init__(self, results_path: Path):
        self.results_path = results_path
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setLevel(logging.INFO)

    def __enter__(self):
        self._audit_logger.addHandler(self.handler)
        self._audit_logger.setLevel(logging.INFO)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._audit_logger.removeHandler(self.handler)
        self._audit_logger.setLevel(logging.ERROR)

        text = self.stream.getvalue()
        records = [json.loads(line) for line in text.split('\n') if line]
        with self.results_path.open('w') as f:
            json.dump(records, f, indent=4)

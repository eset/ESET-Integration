import logging
from dataclasses import dataclass


@dataclass
class RuleMetrics:
    all: int = 0
    parsing_fail: int = 0

    def inc_all(self) -> None:
        self.all += 1

    def inc_parsing_fail(self) -> None:
        self.parsing_fail += 1

    def log_metrics(self) -> None:
        logging.info(f"All rules {self.all} rules")
        logging.info(f"Failed to parse {self.parsing_fail} rules")

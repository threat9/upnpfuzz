import abc
from typing import List


class BaseGenerator:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def name(self) -> str:
        return ""

    @abc.abstractmethod
    def get_request(self) -> List[bytes]:
        return []

    def generate_grammar(self) -> bool:
        return True

    def list(self) -> None:
        return

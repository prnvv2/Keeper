from abc import ABC, abstractmethod
from keeper.core.pipeline import RequestContext


class BaseLayer(ABC):
    name: str = "base"

    @abstractmethod
    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        ...

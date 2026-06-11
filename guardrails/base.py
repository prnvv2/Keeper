from abc import ABC, abstractmethod
from keeper.core.pipeline import RequestContext


class BaseGuardrail(ABC):
    name: str = "base_guardrail"

    @abstractmethod
    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        ...

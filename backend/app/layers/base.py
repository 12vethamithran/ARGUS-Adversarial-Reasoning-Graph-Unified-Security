from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.engine.state import ArgusState
from app.models.finding import Finding


class BaseLayer(ABC):
    layer_id: int
    layer_name: str

    @abstractmethod
    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        """Execute this layer and return findings."""
        ...

    def _finding(self, **kwargs) -> Finding:
        return Finding(layer=self.layer_id, **kwargs)

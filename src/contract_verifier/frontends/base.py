"""Frontend interfaces for lowering source contracts into the unified IR."""

from __future__ import annotations

from abc import ABC, abstractmethod

from contract_verifier.ir.schema import ContractIR


class ContractFrontend(ABC):
    """Parser/lowering boundary for source-language-specific implementations."""

    @abstractmethod
    def parse(self, source: str, *, file_name: str) -> ContractIR:
        """Parse source text and return structurally valid IR."""

"""Solidity frontend scaffold.

TODO: replace placeholder lowering with a real Solidity AST parser while keeping
this module's public interface stable.
"""

from contract_verifier.frontends.base import ContractFrontend
from contract_verifier.ir.schema import ContractIR


class SolidityFrontend(ContractFrontend):
    def parse(self, source: str, *, file_name: str) -> ContractIR:
        return ContractIR(id=file_name, chain="evm", metadata={"frontend": "solidity"})

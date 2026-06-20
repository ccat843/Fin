"""Rust/Anchor frontend scaffold.

TODO: lower Anchor accounts, instructions, constraints, and CPI boundaries into
resources, transitions, guards, effects, and obligations.
"""

from contract_verifier.frontends.base import ContractFrontend
from contract_verifier.ir.schema import ContractIR


class AnchorFrontend(ContractFrontend):
    def parse(self, source: str, *, file_name: str) -> ContractIR:
        return ContractIR(id=file_name, chain="solana", metadata={"frontend": "anchor"})

"""AI-assisted invariant generation boundary.

LLM output is treated as candidate obligations only. Verification decisions are
reserved for symbolic execution plus constraint solving.
"""

from contract_verifier.ir.schema import ContractIR, Obligation


class AIPropertyGenerator:
    def generate(self, ir: ContractIR) -> tuple[Obligation, ...]:
        return ()

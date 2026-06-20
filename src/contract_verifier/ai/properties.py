"""AI-assisted vulnerability hypothesis boundary.

AI output is untrusted. It may suggest vulnerability hypotheses or missing
confirmation invariants, but symbolic execution and the solver remain the only
components allowed to confirm exploitability.
"""

from contract_verifier.ir.schema import ContractIR, Obligation
from contract_verifier.vulnerability.patterns import VulnerabilityHypothesis


class AIPropertyGenerator:
    """Compatibility boundary for future AI-suggested audit leads."""

    def generate(self, ir: ContractIR) -> tuple[Obligation, ...]:
        """Return missing invariant suggestions only; never confirmed findings."""
        return ()

    def generate_hypotheses(self, ir: ContractIR) -> tuple[VulnerabilityHypothesis, ...]:
        """Return untrusted vulnerability hypotheses for symbolic validation."""
        return ()

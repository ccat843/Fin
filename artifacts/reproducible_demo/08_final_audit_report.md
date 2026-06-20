# Audit Report

## Executive Summary
Audited 3 contract(s) and found 1 failed invariant(s); highest severity is critical.

## Threat Model
- **assets**: ['balance', 'owner']
- **contracts**: ['examples/anchor/vault.rs', 'OwnableVault', 'VulnerableVault']
- **principals**: ['contract owner', 'external caller', 'attacker']
- **trust_boundaries**: ['msg.sender', 'Anchor account constraints']

## Invariants
- **balance_non_negative**: contract=OwnableVault, description=balance must never become negative, severity=high, status=pass
- **balance_non_negative**: contract=VulnerableVault, description=balance must never become negative, severity=high, status=fail

## Verified Properties
- None

## Counterexamples
- **VulnerableVault:balance_non_negative**: attack_trace=['drain'], contract=VulnerableVault, explanation=VulnerableVault violates 'balance must never become negative' in tests/fixtures/VulnerableVault.sol. The feasible path is drain, which leaves balance=-5. The issue is rated critical after escalation analysis., invariant=balance must never become negative, severity=critical, solver_status=sat, source_file=tests/fixtures/VulnerableVault.sol, state_snapshot={'balance': -5}

## Escalation Chains
- **balance_non_negative**: explanation=Escalation is feasible for balance_non_negative; feasible variants=('attacker-caller', 'privileged-caller'); infeasible variants=(); max severity=critical., graph={'edges': [{'feasible': True, 'severity_after': 'critical', 'severity_before': 'low', 'source': 'state:initial', 'target': 'state:1', 'transition': 'drain'}], 'nodes': [{'feasible': True, 'id': 'state:initial', 'label': 'counterexample entry', 'severity': 'low', 'state_snapshot': {}}, {'feasible': True, 'id': 'state:1', 'label': 'after drain', 'severity': 'critical', 'state_snapshot': {'balance': -5}}]}, impact={'asset_loss': 'critical', 'control_flow': 'medium', 'privilege_escalation': 'low', 'state_corruption': 'medium'}, max_severity=critical, max_severity_path=['state:initial', 'state:1'], obligation_id=balance_non_negative, variants=[{'accounts': {}, 'caller': 'attacker', 'feasible': True, 'id': 'attacker-caller', 'solver_proof': None, 'solver_status': 'sat'}, {'accounts': {}, 'caller': 'admin', 'feasible': True, 'id': 'privileged-caller', 'solver_proof': None, 'solver_status': 'sat'}]

## Remediation
- **fix_VulnerableVault:balance_non_negative**: recommendation=Add authorization and precondition checks around drain so balance cannot reach the violating value., why_it_works=The failed invariant is 'balance must never become negative'. Guarding the path and rejecting state updates that would falsify the invariant removes the minimized counterexample from the feasible state space.

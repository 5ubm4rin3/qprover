# Security and Responsible Use

QProver is an offensive-security research tool. Use it only on smart contracts and environments that you own, that an organizer provides for testing, or for which you have explicit authorization.

## Bundled safety boundary

- The bundled demo and MicroBench use fresh local Anvil instances.
- QProver does not require public RPC credentials or wallet private keys for the bundled workflows.
- The release contains no public-chain broadcast workflow.
- Static analysis, hypotheses and solver scores are never treated as confirmed exploits.
- Unsupported invariant/setup semantics fail closed rather than being guessed.

## Reporting a QProver security issue

Do not publish a security-sensitive issue that could compromise proof integrity before it is assessed. Contact the repository owner privately through the GitHub profile/repository contact path.

When reporting, include:

- affected commit/version;
- minimal reproduction;
- whether proof integrity, local process isolation, artifact publication or benchmark evidence is affected;
- expected versus observed behavior.

## Trust model

QProver hardens artifact staging/publication against links, identity swaps and cooperative filesystem races, but it does not claim cryptographic protection against a malicious process with the same local user identity. The host running QProver is part of the trusted computing base.

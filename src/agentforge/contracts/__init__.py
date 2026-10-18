"""v1 message contracts. Validation only. No agent, no network, no store."""

from agentforge.contracts.validate import ContractError, validate

__all__ = ["ContractError", "validate"]

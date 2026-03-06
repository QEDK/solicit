# MerkleDropSBT

A soulbound (non-transferable) ERC-721 token distributed via Merkle-tree allowlists with EIP-712 signature delegation.

## Overview

**MerkleDropSBT** lets an owner publish sequential Merkle roots (tranches). Whitelisted addresses sign an EIP-712 `Claim` message choosing a receiver, then anyone can submit the claim on-chain. Each address may claim at most one token across all tranches. Tokens cannot be transferred or approved — only minted and burned by their owner.

### Key properties

- **Soulbound** — transfers and approvals revert; only mint and burn are permitted.
- **Delegated minting** — the claimant signs an EIP-712 message specifying the receiver, enabling meta-transactions.
- **Merkle-gated** — each tranche has its own Merkle root; claimants must provide a valid proof.
- **One claim per address** — `isClaimed` is keyed by address, so a wallet can only mint once regardless of how many tranches it appears in.
- **Owner-burnable** — token holders can burn their own SBT.
- **Ownable2Step** — ownership uses a two-step transfer for safety.

## Build

```sh
forge build
```

## Test

```sh
forge test
```

## Deployment

```sh
forge create src/MerkleDropSBT.sol:MerkleDropSBT \
  --constructor-args <OWNER_ADDRESS> <BASE_URI> \
  --rpc-url <RPC_URL> \
  --private-key <DEPLOYER_KEY>
```

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

import {ERC721URIStorage, ERC721} from "openzeppelin-contracts/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {IERC721} from "openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";
import {Ownable2Step, Ownable} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";

/// @title MerkleDropSBT
/// @author QEDK (@qedk)
/// @notice A soulbound ERC-721 token distributed via Merkle tree allowlists
contract MerkleDropSBT is ERC721URIStorage, EIP712, Ownable2Step {
    using Strings for uint256;

    /// @notice EIP-712 typed data for a mint claim
    struct Claim {
        uint256 trancheId;
        address claimant;
        address receiver;
    }

    /// @notice The next tranche ID that will be assigned when {addRoot} is called
    uint256 public trancheId;

    /// @notice The next token ID that will be minted
    uint256 public tokenId;

    /// @notice Maps a tranche ID to its Merkle root
    mapping(uint256 => bytes32) public merkleRoots;

    /// @notice Tracks whether a given claimant has already claimed
    mapping(address => bool) public isClaimed;

    /// @dev EIP-712 typehash for the {Claim} struct, used when computing the digest to sign
    bytes32 private constant CLAIM_TYPEHASH = keccak256("Claim(uint256 trancheId,address claimant,address receiver)");

    /// @notice Emitted when a new distribution tranche is created
    event NewTranche(uint256 indexed trancheId, bytes32 merkleRoot);

    /// @dev Thrown when a claimant attempts to claim the same tranche twice
    error AlreadyClaimed();
    /// @dev Thrown on any attempt to transfer a soulbound token
    error CannotTransferSoulboundToken();
    /// @dev Thrown on any attempt to set approval for a soulbound token
    error CannotApproveSoulboundToken();
    /// @dev Thrown when the Merkle proof does not verify against the tranche root
    error InvalidProof();
    /// @dev Thrown when the recovered EIP-712 signer does not match the claim's claimant
    error InvalidSignature();
    /// @dev Thrown when the claim references a tranche ID that has not been created yet
    error InvalidTrancheId();
    /// @dev Thrown when a non-owner attempts to burn a token
    error OnlyTokenOwner();
    /// @dev Thrown when the owner attempts to add a zero Merkle root
    error RootCannotBeZero();

    /// @notice Constructor for the SBT contract
    /// @param _owner The initial owner address
    constructor(address _owner) Ownable(_owner) ERC721("Monad Cards", "CARDS") EIP712("Monad Cards", "1") {}

    /// @notice Adds a new Merkle root for a distribution tranche
    /// @dev Increments {trancheId} after assignment, so tranche IDs are sequential starting from 0
    /// @param newRoot The Merkle root of the allowlist. Must not be `bytes32(0)`
    function addRoot(bytes32 newRoot) external onlyOwner {
        require(newRoot != bytes32(0), RootCannotBeZero());
        uint256 currentTrancheId = trancheId;
        merkleRoots[currentTrancheId] = newRoot;

        emit NewTranche(currentTrancheId, newRoot);

        unchecked {
            ++trancheId;
        }
    }

    /// @notice Mints a soulbound token to receiver if the claim is valid
    /// @param claim     The claim struct containing tranche ID, claimant, and receiver
    /// @param signature The EIP-712 signature over the claim, produced by `claim.claimant`
    /// @param proof     The Merkle proof demonstrating inclusion of the claimant in the tranche
    function mint(Claim calldata claim, bytes calldata signature, bytes32[] calldata proof) external {
        require(claim.trancheId < trancheId, InvalidTrancheId());
        bytes32 digest =
            _hashTypedDataV4(keccak256(abi.encode(CLAIM_TYPEHASH, claim.trancheId, claim.claimant, claim.receiver)));
        address signer = ECDSA.recoverCalldata(digest, signature);
        require(signer == claim.claimant, InvalidSignature());
        bytes32 leaf = keccak256(abi.encodePacked(claim.trancheId, claim.claimant));
        require(MerkleProof.verifyCalldata(proof, merkleRoots[claim.trancheId], leaf), InvalidProof());
        require(!isClaimed[claim.claimant], AlreadyClaimed());
        uint256 currentTokenId = tokenId;
        isClaimed[claim.claimant] = true;
        unchecked {
            ++tokenId;
        }
        _safeMint(claim.receiver, currentTokenId);
        _setTokenURI(currentTokenId, string.concat(claim.trancheId.toString(), "/", currentTokenId.toString()));
    }

    /// @notice Burns a soulbound token that the caller owns
    /// @param id The token ID to burn
    function burn(uint256 id) external {
        require(msg.sender == ownerOf(id), OnlyTokenOwner());
        _burn(id);
        _setTokenURI(id, "");
    }

    /// @notice Always reverts since soulbound tokens cannot be approved
    function approve(address, uint256) public virtual override(ERC721, IERC721) {
        revert CannotApproveSoulboundToken();
    }

    /// @notice Always reverts since soulbound tokens cannot have operator approvals
    function setApprovalForAll(address, bool) public virtual override(ERC721, IERC721) {
        revert CannotApproveSoulboundToken();
    }

    /// @dev Overrides ERC-721 internal transfer hook to enforce soulbound semantics
    /// Reverts if both the current owner and to address are non-zero
    /// Mints and burns are permitted
    function _update(address to, uint256 tokenId_, address auth) internal virtual override returns (address) {
        if (_ownerOf(tokenId_) != address(0) && to != address(0)) {
            revert CannotTransferSoulboundToken();
        }

        return super._update(to, tokenId_, auth);
    }

    /// @notice Returns the base URI prepended to every token URI
    /// @return The base URI string
    function _baseURI() internal pure override returns (string memory) {
        return "https://sbt.monad.xyz/";
    }
}

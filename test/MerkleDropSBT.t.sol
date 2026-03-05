// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {MerkleDropSBT} from "../src/MerkleDropSBT.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC721Receiver} from "openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC721Errors} from "openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol";

/// @dev A contract receiver that correctly implements IERC721Receiver.
contract GoodReceiver is IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}

/// @dev A contract receiver that does NOT implement IERC721Receiver (reverts).
contract BadReceiver {}

contract MerkleDropSBTTest is Test {
    MerkleDropSBT internal drop;

    uint256 internal claimantPrivateKey;
    address internal claimant;
    uint256 internal claimant2PrivateKey;
    address internal claimant2;
    address internal receiver;
    address internal other;

    bytes32 internal constant CLAIM_TYPEHASH = keccak256("Claim(uint256 trancheId,address claimant,address receiver)");
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function setUp() public {
        drop = new MerkleDropSBT(address(this));

        claimantPrivateKey = 0xA11CE;
        claimant = vm.addr(claimantPrivateKey);
        claimant2PrivateKey = 0xB0B;
        claimant2 = vm.addr(claimant2PrivateKey);
        receiver = makeAddr("receiver");
        other = makeAddr("other");

        // Tranche 0: single-leaf tree (root == leaf)
        bytes32 root = _leaf(0, claimant);
        drop.addRoot(root);
    }

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    function test_MintSuccess() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});

        bytes memory signature = _signClaim(claim);
        bytes32[] memory proof = new bytes32[](0);

        drop.mint(claim, signature, proof);

        assertEq(drop.ownerOf(0), receiver);
        assertEq(drop.tokenURI(0), "https://sbt.monad.xyz/0/0");
        assertEq(drop.tokenId(), 1);
        assertTrue(drop.isClaimed(_leaf(0, claimant)));
    }

    // -----------------------------------------------------------------------
    // Multi-tranche tests
    // -----------------------------------------------------------------------

    function test_MintAcrossMultipleTranches() public {
        // Add tranche 1 with a different claimant
        bytes32 root1 = _leaf(1, claimant2);
        drop.addRoot(root1);

        // Mint from tranche 0
        MerkleDropSBT.Claim memory claim0 = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        drop.mint(claim0, _signClaim(claim0), new bytes32[](0));
        assertEq(drop.ownerOf(0), receiver);
        assertEq(drop.tokenURI(0), "https://sbt.monad.xyz/0/0");

        // Mint from tranche 1
        MerkleDropSBT.Claim memory claim1 = MerkleDropSBT.Claim({trancheId: 1, claimant: claimant2, receiver: other});
        drop.mint(claim1, _signWithKey(claim1, claimant2PrivateKey), new bytes32[](0));
        assertEq(drop.ownerOf(1), other);
        assertEq(drop.tokenURI(1), "https://sbt.monad.xyz/1/1");
    }

    function test_SameClaimantDifferentTranches() public {
        // Claimant is in tranche 0 and tranche 1
        bytes32 root1 = _leaf(1, claimant);
        drop.addRoot(root1);

        MerkleDropSBT.Claim memory claim0 = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        drop.mint(claim0, _signClaim(claim0), new bytes32[](0));

        MerkleDropSBT.Claim memory claim1 = MerkleDropSBT.Claim({trancheId: 1, claimant: claimant, receiver: receiver});
        drop.mint(claim1, _signClaim(claim1), new bytes32[](0));

        assertEq(drop.ownerOf(0), receiver);
        assertEq(drop.ownerOf(1), receiver);
    }

    // -----------------------------------------------------------------------
    // Multi-leaf Merkle tree (with actual proof verification)
    // -----------------------------------------------------------------------

    function test_MintWithRealMerkleProof() public {
        // Build a 2-leaf tree for tranche 2
        bytes32 leafA = _leaf(2, claimant);
        bytes32 leafB = _leaf(2, claimant2);
        bytes32 root = _hashPair(leafA, leafB);

        drop.addRoot(root); // tranche 1
        drop.addRoot(root); // tranche 2

        // Claimant A mints with leafB as proof sibling
        MerkleDropSBT.Claim memory claimA = MerkleDropSBT.Claim({trancheId: 2, claimant: claimant, receiver: receiver});
        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = leafB;
        drop.mint(claimA, _signClaim(claimA), proofA);
        assertEq(drop.ownerOf(drop.tokenId() - 1), receiver);

        // Claimant B mints with leafA as proof sibling
        MerkleDropSBT.Claim memory claimB = MerkleDropSBT.Claim({trancheId: 2, claimant: claimant2, receiver: other});
        bytes32[] memory proofB = new bytes32[](1);
        proofB[0] = leafA;
        drop.mint(claimB, _signWithKey(claimB, claimant2PrivateKey), proofB);
        assertEq(drop.ownerOf(drop.tokenId() - 1), other);
    }

    // -----------------------------------------------------------------------
    // Burn tests
    // -----------------------------------------------------------------------

    function test_BurnSuccess() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        drop.mint(claim, _signClaim(claim), new bytes32[](0));
        assertEq(drop.ownerOf(0), receiver);

        vm.prank(receiver);
        drop.burn(0);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, 0));
        drop.ownerOf(0);
    }

    function test_RevertIf_BurnByNonOwner() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        drop.mint(claim, _signClaim(claim), new bytes32[](0));

        vm.prank(other);
        vm.expectRevert(MerkleDropSBT.OnlyTokenOwner.selector);
        drop.burn(0);
    }

    function test_RevertIf_BurnNonexistentToken() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, 999));
        drop.burn(999);
    }

    function test_BurnDoesNotResetClaim() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);
        drop.mint(claim, signature, new bytes32[](0));

        vm.prank(receiver);
        drop.burn(0);

        // The claim leaf remains used — cannot re-mint
        assertTrue(drop.isClaimed(_leaf(0, claimant)));
        vm.expectRevert(MerkleDropSBT.AlreadyClaimed.selector);
        drop.mint(claim, signature, new bytes32[](0));
    }

    // -----------------------------------------------------------------------
    // addRoot tests
    // -----------------------------------------------------------------------

    function test_RevertIf_AddZeroRoot() public {
        vm.expectRevert(MerkleDropSBT.RootCannotBeZero.selector);
        drop.addRoot(bytes32(0));
    }

    function test_RevertIf_AddRootNotOwner() public {
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), other));
        drop.addRoot(keccak256("root"));
    }

    function test_AddRootIncrementsTrancheId() public {
        assertEq(drop.trancheId(), 1); // setUp added one
        drop.addRoot(keccak256("root2"));
        assertEq(drop.trancheId(), 2);
        drop.addRoot(keccak256("root3"));
        assertEq(drop.trancheId(), 3);
    }

    // -----------------------------------------------------------------------
    // Invalid tranche ID
    // -----------------------------------------------------------------------

    function test_RevertIf_InvalidTrancheId() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 999, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);
        vm.expectRevert(MerkleDropSBT.InvalidTrancheId.selector);
        drop.mint(claim, signature, new bytes32[](0));
    }

    // -----------------------------------------------------------------------
    // Receiver is a contract
    // -----------------------------------------------------------------------

    function test_MintToContractReceiver() public {
        GoodReceiver goodReceiver = new GoodReceiver();
        MerkleDropSBT.Claim memory claim =
            MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: address(goodReceiver)});
        bytes memory signature = _signClaim(claim);
        drop.mint(claim, signature, new bytes32[](0));
        assertEq(drop.ownerOf(0), address(goodReceiver));
    }

    function test_RevertIf_MintToBadContractReceiver() public {
        BadReceiver badReceiver = new BadReceiver();
        MerkleDropSBT.Claim memory claim =
            MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: address(badReceiver)});
        bytes memory signature = _signClaim(claim);
        vm.expectRevert();
        drop.mint(claim, signature, new bytes32[](0));
    }

    // -----------------------------------------------------------------------
    // Receiver is address(0) — should revert via OZ ERC721
    // -----------------------------------------------------------------------

    function test_RevertIf_MintToZeroAddress() public {
        // Build a new tranche with a root that includes this claimant (single leaf)
        // The EIP-712 signature signs over receiver=address(0) and proof is valid,
        // but _safeMint should revert via OZ's ERC721InvalidReceiver.
        bytes32 root1 = _leaf(1, claimant);
        drop.addRoot(root1);

        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 1, claimant: claimant, receiver: address(0)});
        bytes memory signature = _signClaim(claim);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector, address(0)));
        drop.mint(claim, signature, new bytes32[](0));
    }

    // -----------------------------------------------------------------------
    // Signature edge cases
    // -----------------------------------------------------------------------

    function test_RevertIf_SignedByWrongKey() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        // Sign with a different key
        bytes memory wrongSig = _signWithKey(claim, claimant2PrivateKey);
        vm.expectRevert(MerkleDropSBT.InvalidSignature.selector);
        drop.mint(claim, wrongSig, new bytes32[](0));
    }

    function test_RevertIf_SignatureReplay_DifferentReceiver() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);

        // Tamper with the receiver
        MerkleDropSBT.Claim memory tampered = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: other});

        vm.expectRevert(MerkleDropSBT.InvalidSignature.selector);
        drop.mint(tampered, signature, new bytes32[](0));
    }

    // -----------------------------------------------------------------------
    // Transfer / approval reverts (carried forward)
    // -----------------------------------------------------------------------

    function test_RevertIf_InvalidSignature() public {
        MerkleDropSBT.Claim memory signedClaim =
            MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(signedClaim);

        MerkleDropSBT.Claim memory submittedClaim =
            MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: other});

        vm.expectRevert(MerkleDropSBT.InvalidSignature.selector);
        drop.mint(submittedClaim, signature, new bytes32[](0));
    }

    function test_RevertIf_InvalidProof() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = keccak256("invalid-proof-node");

        vm.expectRevert(MerkleDropSBT.InvalidProof.selector);
        drop.mint(claim, signature, invalidProof);
    }

    function test_RevertIf_AlreadyClaimed() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);

        drop.mint(claim, signature, new bytes32[](0));

        vm.expectRevert(MerkleDropSBT.AlreadyClaimed.selector);
        drop.mint(claim, signature, new bytes32[](0));
    }

    function test_RevertIf_Transfer() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);
        drop.mint(claim, signature, new bytes32[](0));

        vm.prank(receiver);
        vm.expectRevert(MerkleDropSBT.CannotTransferSoulboundToken.selector);
        drop.transferFrom(receiver, other, 0);
    }

    function test_RevertIf_SafeTransferOverloads() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);
        drop.mint(claim, signature, new bytes32[](0));

        vm.startPrank(receiver);

        vm.expectRevert(MerkleDropSBT.CannotTransferSoulboundToken.selector);
        drop.safeTransferFrom(receiver, other, 0);

        vm.expectRevert(MerkleDropSBT.CannotTransferSoulboundToken.selector);
        drop.safeTransferFrom(receiver, other, 0, "");

        vm.stopPrank();
    }

    function test_RevertIf_Approvals() public {
        MerkleDropSBT.Claim memory claim = MerkleDropSBT.Claim({trancheId: 0, claimant: claimant, receiver: receiver});
        bytes memory signature = _signClaim(claim);
        drop.mint(claim, signature, new bytes32[](0));

        vm.prank(receiver);
        vm.expectRevert(MerkleDropSBT.CannotApproveSoulboundToken.selector);
        drop.approve(other, 0);

        vm.prank(receiver);
        vm.expectRevert(MerkleDropSBT.CannotApproveSoulboundToken.selector);
        drop.setApprovalForAll(other, true);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _signClaim(MerkleDropSBT.Claim memory claim) internal view returns (bytes memory) {
        return _signWithKey(claim, claimantPrivateKey);
    }

    function _signWithKey(MerkleDropSBT.Claim memory claim, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 digest = _claimDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _claimDigest(MerkleDropSBT.Claim memory claim) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, claim.trancheId, claim.claimant, claim.receiver));
        return MessageHashUtils.toTypedDataHash(_domainSeparator(), structHash);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("MerkleDropSBT")),
                keccak256(bytes("1")),
                block.chainid,
                address(drop)
            )
        );
    }

    function _leaf(uint256 _trancheId, address account) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_trancheId, account));
    }

    /// @dev Mirrors OpenZeppelin's Hashes.commutativeKeccak256 — sorts before hashing.
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}

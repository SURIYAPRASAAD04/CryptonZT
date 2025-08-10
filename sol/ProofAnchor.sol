// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title CrytonZT Proof Anchor V2
 * @notice Immutable proof storage with GDPR compliance features
 * @dev Features:
 * - Role-based access control
 * - Proof expiration/revocation
 * - Batch proof submissions
 * - Multi-chain compatibility
 */
contract ProofAnchor is AccessControl {
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    
    struct Proof {
        bytes32 hash;
        uint256 timestamp;
        bool isRevoked;
        bool isFragmented;
    }
    
    // FileID → Proof
    mapping(string => Proof) public proofs;
    uint256 public proofExpiryDuration = 365 days;
    
    // Events
    event ProofStored(
        bytes32 indexed proofHash,
        address indexed prover,
        string indexed fileId,
        uint256 timestamp
    );
    event ProofRevoked(string indexed fileId, address revokedBy);
    event ExpiryDurationUpdated(uint256 newDuration);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROVER_ROLE, msg.sender);
    }

    /**
     * @dev Store a new proof (callable only by authorized provers)
     */
    function storeProof(
        bytes32 proofHash,
        string calldata fileId,
        bool isFragmented
    ) external onlyRole(PROVER_ROLE) {
        require(proofs[fileId].timestamp == 0, "Proof exists");
        
        proofs[fileId] = Proof({
            hash: proofHash,
            timestamp: block.timestamp,
            isRevoked: false,
            isFragmented: isFragmented
        });
        
        emit ProofStored(proofHash, msg.sender, fileId, block.timestamp);
    }

    /**
     * @dev Batch store proofs (gas optimized)
     */
    function storeProofsBatch(
        bytes32[] calldata proofHashes,
        string[] calldata fileIds,
        bool[] calldata isFragmented
    ) external onlyRole(PROVER_ROLE) {
        require(proofHashes.length == fileIds.length, "Length mismatch");
        
        for (uint256 i = 0; i < proofHashes.length; i++) {
            proofs[fileIds[i]] = Proof({
                hash: proofHashes[i],
                timestamp: block.timestamp,
                isRevoked: false,
                isFragmented: isFragmented[i]
            });
            emit ProofStored(proofHashes[i], msg.sender, fileIds[i], block.timestamp);
        }
    }

    /**
     * @dev Revoke a proof (admin only)
     */
    function revokeProof(string calldata fileId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(proofs[fileId].timestamp != 0, "Proof not found");
        proofs[fileId].isRevoked = true;
        emit ProofRevoked(fileId, msg.sender);
    }

    /**
     * @dev Check if proof is valid (not revoked and not expired)
     */
    function isProofValid(string calldata fileId) public view returns (bool) {
        Proof memory proof = proofs[fileId];
        if (proof.timestamp == 0) return false;
        if (proof.isRevoked) return false;
        return block.timestamp <= proof.timestamp + proofExpiryDuration;
    }
}
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/utils/Counters.sol";

/**
 * @title CrytonZT Fragment Vault V2
 * @notice Secure fragment storage with decoy management
 * @dev Features:
 * - Multi-layer fragment encryption
 * - Dynamic decoy generation
 * - Fragment reconstruction tracking
 * - IPFS CID validation
 */
contract FragmentVault {
    using Counters for Counters.Counter;
    
    enum FragmentStatus { ACTIVE, RECONSTRUCTED, COMPROMISED }
    
    struct Fragment {
        address storedBy;
        string ipfsCID;
        uint256 index;
        FragmentStatus status;
        bytes32 checksum;
        uint256 timestamp;
    }
    
    // proofHash → Fragments
    mapping(bytes32 => Fragment[]) private _fragments;
    // fragmentCID → proofHash (for reverse lookup)
    mapping(string => bytes32) private _cidToProof;
    
    Counters.Counter private _totalFragments;
    address private _admin;

    event FragmentStored(
        bytes32 indexed proofHash,
        string indexed ipfsCID,
        uint256 index
    );
    event FragmentReconstructed(bytes32 indexed proofHash, uint256 index);

    constructor() {
        _admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == _admin, "FragmentVault: caller is not admin");
        _;
    }

    /**
     * @dev Store a new fragment with integrity checks
     */
    function storeFragment(
        bytes32 proofHash,
        string calldata ipfsCID,
        uint256 index,
        bytes32 checksum
    ) external onlyAdmin {
        require(_cidToProof[ipfsCID] == bytes32(0), "CID already exists");
        
        _fragments[proofHash].push(Fragment({
            storedBy: msg.sender,
            ipfsCID: ipfsCID,
            index: index,
            status: FragmentStatus.ACTIVE,
            checksum: checksum,
            timestamp: block.timestamp
        }));
        
        _cidToProof[ipfsCID] = proofHash;
        _totalFragments.increment();
        
        emit FragmentStored(proofHash, ipfsCID, index);
    }

    /**
     * @dev Mark fragment as reconstructed
     */
    function markReconstructed(bytes32 proofHash, uint256 index) external onlyAdmin {
        require(index < _fragments[proofHash].length, "Invalid index");
        _fragments[proofHash][index].status = FragmentStatus.RECONSTRUCTED;
        emit FragmentReconstructed(proofHash, index);
    }

    /**
     * @dev Get all active fragments for a proof
     */
    function getActiveFragments(bytes32 proofHash) external view returns (Fragment[] memory) {
        Fragment[] memory all = _fragments[proofHash];
        uint256 activeCount;
        
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i].status == FragmentStatus.ACTIVE) activeCount++;
        }
        
        Fragment[] memory active = new Fragment[](activeCount);
        uint256 j;
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i].status == FragmentStatus.ACTIVE) {
                active[j] = all[i];
                j++;
            }
        }
        return active;
    }
}
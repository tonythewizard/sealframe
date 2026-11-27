// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title SealFrameAnchor — On-Chain 32-Byte Commitment & Optimistic Verifiable Inference Registry
/// @notice Matches SealFrame C11 EVM adapter (src/chain_adapters.c):
///         - anchor(bytes32,bytes32,uint64)
///         - isAnchored(bytes32)
contract SealFrameAnchor {
    struct AnchorRecord {
        bytes32 targetDna;
        uint64  serial;
        uint64  timestamp;
        address submitter;
        bool    exists;
        bool    slashed;
    }

    uint64  public constant CHALLENGE_WINDOW = 600; // 10 minutes optimistic window
    uint256 public constant MIN_STAKE        = 0.01 ether;

    mapping(bytes32 => AnchorRecord) public records;
    mapping(address => uint256)      public stakes;

    event Anchored(bytes32 indexed commitment, bytes32 indexed targetDna, uint64 serial, address indexed submitter);
    event FraudSlashed(bytes32 indexed commitment, address indexed offender, address indexed challenger, uint256 reward);

    function depositStake() external payable {
        require(msg.value > 0, "zero stake");
        stakes[msg.sender] += msg.value;
    }

    function anchor(bytes32 commitment, bytes32 targetDna, uint64 serial) external {
        require(commitment != bytes32(0), "zero commitment");
        require(!records[commitment].exists, "already anchored");
        records[commitment] = AnchorRecord({
            targetDna: targetDna,
            serial:    serial,
            timestamp: uint64(block.timestamp),
            submitter: msg.sender,
            exists:    true,
            slashed:   false
        });
        emit Anchored(commitment, targetDna, serial, msg.sender);
    }

    function isAnchored(bytes32 commitment) external view returns (bool) {
        AnchorRecord storage r = records[commitment];
        return r.exists && !r.slashed;
    }

    /// @notice Slash a Byzantine submitter during the optimistic challenge window given a verified fraud proof.
    /// @dev Integrate an Ed25519 verifier precompile / Stylus module to verify the FPD1 signature on-chain.
    function slashWithProof(bytes32 commitment, bytes calldata fpd1Receipt, bytes32 honestResultDna) external {
        AnchorRecord storage r = records[commitment];
        require(r.exists && !r.slashed, "not active");
        require(block.timestamp <= r.timestamp + CHALLENGE_WINDOW, "window closed");
        require(fpd1Receipt.length >= 160 && honestResultDna != r.targetDna, "invalid proof");

        r.slashed = true;
        uint256 penalty = stakes[r.submitter];
        if (penalty > 0) {
            stakes[r.submitter] = 0;
            (bool ok, ) = payable(msg.sender).call{value: penalty}("");
            require(ok, "reward transfer failed");
        }
        emit FraudSlashed(commitment, r.submitter, msg.sender, penalty);
    }
}

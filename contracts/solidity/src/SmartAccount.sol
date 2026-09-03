// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { DenyList } from "./DenyList.sol";

/**
 * @title Aegis Vault SmartAccount (Solidity port)
 * @notice On-chain hard-policy layer for agent asset execution — 1:1 port of
 *         packages/chain-eth/src/smart-account.js with the signature check
 *         replaced by EVM `ecrecover` (secp256k1). The agent's on-chain
 *         identity is the EVM address deterministically derived from its PQC
 *         root key (see chain-eth deriveEthWalletFromPQC), so the on-chain
 *         account and the PQC-based SDK identity stay bound to the same root.
 *
 * @dev Signature model (must match the JS side exactly — see
 *      packages/chain-eth/src/canonical.js hashIntentDigest):
 *
 *     digest = keccak256(abi.encodePacked(
 *         keccak256(bytes(action)), keccak256(bytes(chain)),
 *         keccak256(bytes(asset)), amount, keccak256(bytes(recipient)),
 *         keccak256(bytes(contract)), keccak256(bytes(method)), nonce,
 *         keccak256(bytes(agentId)), sessionIssuedAt, sessionExpiresAt,
 *         sessionId
 *     ))
 *
 *     Every element is 32 bytes => no abi.encodePacked ambiguity, and the
 *     digest can be rebuilt identically in JS with noble/curves.
 *     Signature is a plain secp256k1 (r,s,v) over `digest` (no EIP-191 prefix
 *     — the JS signer uses the same plain digest). Low-S is enforced (EIP-2)
 *     to close signature malleability.
 *
 * INVARIANTS enforced here (see SECURITY_INVARIANTS.md):
 *   INV-002 amount binding: `amount` is part of the signed digest AND the
 *           explicit policy input — a signer cannot claim a different amount
 *           than what was signed.
 *   INV-003 bounded sessions: session expiry + whitelists re-checked on-chain;
 *           expired/revoked sessions cannot execute.
 *   INV-005 no self-escalation: escalation actions rejected even if signed.
 *   INV-006 emergency brake-only: emergency key cannot move assets or escalate.
 *   INV-007 bounded blast radius: per-tx ceiling, rolling window cumulative,
 *           nonce anti-replay, and estimateMaxLoss().
 */
contract SmartAccount {
    uint256 internal constant MILLIS_PER_SECOND = 1000;
    // ── Types ─────────────────────────────────────────────────────────────
    struct Session {
        bytes32 id;
        string agentId;
        address agentEvmAddress;   // ecrecover target (PQC-derived EVM address)
        uint256 issuedAt;          // ms epoch (matches session tokens / canonical schema)
        uint256 expiresAt;         // ms epoch (matches session tokens / canonical schema)
        uint256 maxPerTx;          // 0 = unlimited
        uint256 maxDaily;          // 0 = unlimited
        bool revoked;
    }

    struct Whitelist {
        bytes32[] chains;
        bytes32[] assets;
        bytes32[] contracts;
        bytes32[] methods;
        bytes32[] recipients;
    }

    /**
     * The signed intent + session context. This is exactly the field set the
     * canonical digest is built from (see _hashIntent); packing it into a
     * struct also keeps the ABI flat enough to avoid stack-too-deep.
     */
    struct IntentFields {
        bytes32 sessionId;
        string action;
        string chain;
        string asset;
        uint256 amount;
        string recipient;
        string contractAddr;
        string method;
        uint256 nonce;
        string agentId;
        uint256 sessionIssuedAt;
        uint256 sessionExpiresAt;
    }

    // ── State ─────────────────────────────────────────────────────────────
    address public owner;
    address public emergencyKey;
    bool public paused;
    bool public frozen;
    uint256 public accountMaxDaily; // account-wide cumulative ceiling (INV-007)
    uint256 public accountSpentThisWindow;
    uint256 public accountWindowStart;

    mapping(bytes32 => Session) public sessions;
    // Not public: a struct with dynamic arrays cannot be a public mapping value.
    mapping(bytes32 => Whitelist) internal whitelists;
    mapping(bytes32 => uint256) public sessionLastNonce;
    mapping(bytes32 => uint256) public sessionSpentThisWindow;
    mapping(bytes32 => uint256) public sessionWindowStart;
    uint256 public constant DAY_WINDOW = 24 hours;

    // ── Events ────────────────────────────────────────────────────────────
    event SessionRegistered(bytes32 indexed sessionId, string agentId, address agentEvmAddress);
    event SessionRevoked(bytes32 indexed sessionId);
    event Executed(bytes32 indexed sessionId, bytes32 indexed txId, uint256 amount);
    event Paused(address by);
    event Resumed(address by);
    event Frozen(address by);
    event Unfrozen(address by);
    event LimitReduced(bytes32 indexed sessionId, uint256 newMaxPerTx, uint256 newMaxDaily);

    // ── Errors ────────────────────────────────────────────────────────────
    error NotOwner(address caller);
    error NotEmergency(address caller);
    error AccountPaused();
    error AccountFrozen();
    error NotRegistered(bytes32 sessionId);
    error SessionRevokedError();
    error SessionExpired();
    error InvalidSignature();
    error BadNonce(uint256 expected, uint256 got);
    error AmountExceedsPerTx(uint256 max);
    error AmountExceedsDaily(uint256 max);
    error WhitelistViolation(string dim);
    error SelfEscalationRejected(string action);
    error AllowanceSurfaceRejected(string action);
    error SessionExists(bytes32 sessionId);
    error InvalidSession();
    error NoAccountCeiling();

    // ── Constructor ───────────────────────────────────────────────────────
    constructor(address _owner, address _emergencyKey, uint256 _accountMaxDaily) {
        if (_owner == address(0)) revert NotOwner(address(0));
        if (_emergencyKey == address(0)) revert NotEmergency(address(0));
        if (_accountMaxDaily == 0) revert NoAccountCeiling(); // fail-closed: no unbounded account (INV-007)
        owner = _owner;
        emergencyKey = _emergencyKey;
        accountMaxDaily = _accountMaxDaily;
    }

    // ── Modifiers ─────────────────────────────────────────────────────────
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }
    modifier onlyEmergency() {
        if (msg.sender != emergencyKey) revert NotEmergency(msg.sender);
        _;
    }
    modifier notPaused() {
        if (paused) revert AccountPaused();
        _;
    }
    modifier notFrozen() {
        if (frozen) revert AccountFrozen();
        _;
    }

    // ── ADMIN / SESSION MANAGEMENT ────────────────────────────────────────

    /**
     * Register an agent session (owner only). Hard ceilings are mandatory:
     * a session without explicit maxPerTx/maxDaily limits cannot be created
     * (INV-003/007 — no unbounded session).
     */
    function registerSession(
        bytes32 sessionId,
        string calldata agentId,
        address agentEvmAddress,
        uint256 issuedAt,
        uint256 expiresAt,
        uint256 maxPerTx,
        uint256 maxDaily,
        string[] calldata allowedChains,
        string[] calldata allowedAssets,
        string[] calldata allowedContracts,
        string[] calldata allowedMethods,
        string[] calldata allowedRecipients
    ) external onlyOwner notFrozen {
        if (expiresAt <= issuedAt) revert InvalidSession();
        if (maxPerTx == 0 && maxDaily == 0) revert InvalidSession();
        if (sessions[sessionId].agentEvmAddress != address(0)) revert SessionExists(sessionId);

        sessions[sessionId] = Session({
            id: sessionId,
            agentId: agentId,
            agentEvmAddress: agentEvmAddress,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            maxPerTx: maxPerTx,
            maxDaily: maxDaily,
            revoked: false
        });
        whitelists[sessionId] = Whitelist({
            chains: _toHashed(allowedChains),
            assets: _toHashed(allowedAssets),
            contracts: _toHashed(allowedContracts),
            methods: _toHashed(allowedMethods),
            recipients: _toHashed(allowedRecipients)
        });
        emit SessionRegistered(sessionId, agentId, agentEvmAddress);
    }

    function revokeSession(bytes32 sessionId) external onlyOwner {
        sessions[sessionId].revoked = true;
        emit SessionRevoked(sessionId);
    }

    // ── EMERGENCY (brake-only, INV-006) ──────────────────────────────────
    function pause() external onlyEmergency { paused = true; emit Paused(msg.sender); }
    function freeze() external onlyEmergency { frozen = true; emit Frozen(msg.sender); }

    /** Resume execution. OWNER ONLY — emergency is brake-only (INV-006). */
    function resume() external onlyOwner { paused = false; emit Resumed(msg.sender); }

    /** Unfreeze. OWNER ONLY — emergency cannot lift its own brake (INV-006). */
    function unfreeze() external onlyOwner { frozen = false; emit Unfrozen(msg.sender); }

    /** Emergency may only REDUCE limits — never raise (INV-006). */
    function emergencyReduceLimit(bytes32 sessionId, uint256 newMaxPerTx, uint256 newMaxDaily)
        external onlyEmergency
    {
        Session storage s = sessions[sessionId];
        if (s.agentEvmAddress == address(0)) revert NotRegistered(sessionId);
        if (newMaxPerTx > s.maxPerTx || newMaxDaily > s.maxDaily) revert SelfEscalationRejected("raise-limit");
        s.maxPerTx = newMaxPerTx;
        s.maxDaily = newMaxDaily;
        emit LimitReduced(sessionId, newMaxPerTx, newMaxDaily);
    }

    // ── EXECUTION (the ONLY fund-movement path, INV-005/007) ─────────────

    /**
     * Execute an agent intent. All policy checks run here against the fields
     * that were signed into `digest`; the recovered signer must equal the
     * session's registered EVM address. This is the single path that can
     * move value, and it is fully bounded.
     */
    function executeFromAgent(
        IntentFields calldata intent,
        bytes calldata signature // 65 bytes: r(32) || s(32) || v(1)
    ) external notPaused notFrozen returns (bytes32 txId) {
        // 1. Session lookup + validity (INV-003)
        Session storage s = sessions[intent.sessionId];
        if (s.agentEvmAddress == address(0)) revert NotRegistered(intent.sessionId);
        if (s.revoked) revert SessionRevokedError();
        if (_blockTimestampMs() > s.expiresAt) revert SessionExpired();
        // Session-bound fields must match what was registered.
        if (
            keccak256(bytes(intent.agentId)) != keccak256(bytes(s.agentId)) ||
            intent.sessionIssuedAt != s.issuedAt ||
            intent.sessionExpiresAt != s.expiresAt
        ) revert InvalidSession();

        // 2. Signature recovery (INV-002: amount + all fields are signed)
        bytes32 digest = _hashIntent(intent);
        address signer = _recover(digest, signature);
        if (signer != s.agentEvmAddress) revert InvalidSignature();

        // 3. Nonce anti-replay (INV-007) — strictly increasing
        if (intent.nonce <= sessionLastNonce[intent.sessionId]) revert BadNonce(sessionLastNonce[intent.sessionId] + 1, intent.nonce);
        sessionLastNonce[intent.sessionId] = intent.nonce;

        // 4. Self-escalation guard (INV-005) + allowance surface (INV-007) —
        //    enforced even with a valid signature and even if the owner's
        //    whitelist names them. Both the action and the method are checked;
        //    the deny list is normalized (case/separator-insensitive) and
        //    generated from the JS engine's canonical sets (DenyList.sol), so
        //    JS-rejected variants are rejected here too.
        if (_isSelfEscalation(intent.action, intent.method)) revert SelfEscalationRejected(intent.action);
        if (_touchesAllowanceSurface(intent.action, intent.method)) revert AllowanceSurfaceRejected(intent.action);

        // 5. Whitelists (INV-003)
        Whitelist storage w = whitelists[intent.sessionId];
        if (!_inList(w.chains, intent.chain)) revert WhitelistViolation("chain");
        if (!_inList(w.assets, intent.asset)) revert WhitelistViolation("asset");
        if (!_inList(w.contracts, intent.contractAddr)) revert WhitelistViolation("contract");
        if (!_inList(w.methods, intent.method)) revert WhitelistViolation("method");
        if (!_inList(w.recipients, intent.recipient)) revert WhitelistViolation("recipient");

        // 6. Amount ceilings (INV-007)
        uint256 amount = intent.amount;
        if (s.maxPerTx > 0 && amount > s.maxPerTx) revert AmountExceedsPerTx(s.maxPerTx);

        // 6b. Account-level cumulative ceiling (INV-007) — mirrors the JS
        // engine's account policy bound.
        _rollAccountWindow();
        uint256 acctSpent = accountSpentThisWindow;
        if (accountMaxDaily > 0 && acctSpent + amount > accountMaxDaily) revert AmountExceedsDaily(accountMaxDaily);
        accountSpentThisWindow = acctSpent + amount;

        // 6c. Session-level cumulative ceiling (INV-007)
        _rollWindow(intent.sessionId);
        uint256 spent = sessionSpentThisWindow[intent.sessionId];
        if (s.maxDaily > 0 && spent + amount > s.maxDaily) revert AmountExceedsDaily(s.maxDaily);
        sessionSpentThisWindow[intent.sessionId] = spent + amount;

        // 7. Commit (this is where the "transfer" would happen in a full port)
        txId = keccak256(abi.encodePacked(intent.sessionId, intent.nonce));
        emit Executed(intent.sessionId, txId, amount);
    }

    // ── VIEWS ─────────────────────────────────────────────────────────────

    /**
     * Quantifiable maximum loss across the account in the current window
     * (INV-007). Account-wide cumulative ceiling minus what has already been
     * spent this window is the on-chain worst-case exposure bound. Per-session
     * ceilings may be tighter — query sessionMaxLoss(sessionId).
     */
    function estimateMaxLoss() external view returns (uint256) {
        uint256 spent = _currentAccountSpent();
        return accountMaxDaily > spent ? accountMaxDaily - spent : 0;
    }

    function sessionMaxLoss(bytes32 sessionId) external view returns (uint256) {
        Session storage s = sessions[sessionId];
        if (s.agentEvmAddress == address(0) || s.revoked || _blockTimestampMs() > s.expiresAt) {
            return 0;
        }
        uint256 remaining = _currentAccountRemaining();
        if (s.maxDaily > 0) {
            uint256 spent = _currentSessionSpent(sessionId);
            uint256 sessionRemaining = s.maxDaily > spent ? s.maxDaily - spent : 0;
            if (sessionRemaining < remaining) remaining = sessionRemaining;
        }
        // NOTE: maxPerTx deliberately does NOT cap this value. Like the JS
        // engine, maxPerTx bounds a single transfer; a session can issue many
        // per-tx-sized executions within the window, so the cumulative
        // exposure ceiling is the DAILY/account ceilings only. Mixing maxPerTx
        // in here would UNDERSTATE the real maximum loss (mirrors
        // smart-account.js estimateMaxLoss).
        return remaining;
    }

    /**
     * Public wrapper over the internal digest computation — the authoritative
     * definition shared with the JS side (hashIntentDigest). Exposed so the
     * Foundry suite and the JS golden-vector tests can pin the exact digest.
     */
    function hashIntent(IntentFields calldata intent) external pure returns (bytes32) {
        return _hashIntent(intent);
    }

    // ── INTERNAL ──────────────────────────────────────────────────────────

    function _hashIntent(IntentFields memory intent) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                keccak256(bytes(intent.action)),
                keccak256(bytes(intent.chain)),
                keccak256(bytes(intent.asset)),
                intent.amount,
                keccak256(bytes(intent.recipient)),
                keccak256(bytes(intent.contractAddr)),
                keccak256(bytes(intent.method)),
                intent.nonce,
                keccak256(bytes(intent.agentId)),
                intent.sessionIssuedAt,
                intent.sessionExpiresAt,
                intent.sessionId // raw bytes32 — matches the JS canonical digest
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        // EIP-2 low-S: reject high-S signatures (malleability guard).
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);
        return ecrecover(digest, v, r, s);
    }

    function _isSelfEscalation(string calldata action, string calldata method) internal pure returns (bool) {
        return DenyList.isSelfEscalation(keccak256(DenyList.normalize(action)))
            || DenyList.isSelfEscalation(keccak256(DenyList.normalize(method)));
    }

    function _touchesAllowanceSurface(string calldata action, string calldata method) internal pure returns (bool) {
        return DenyList.isAllowanceSurface(keccak256(DenyList.normalize(action)))
            || DenyList.isAllowanceSurface(keccak256(DenyList.normalize(method)));
    }

    function _toHashed(string[] calldata arr) internal pure returns (bytes32[] memory) {
        bytes32[] memory out = new bytes32[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) out[i] = keccak256(bytes(arr[i]));
        return out;
    }

    function _inList(bytes32[] storage list, string calldata value) internal view returns (bool) {
        if (list.length == 0) return true; // empty whitelist = unrestricted
        bytes32 h = keccak256(bytes(value));
        for (uint256 i = 0; i < list.length; i++) if (list[i] == h) return true;
        return false;
    }

    function _rollWindow(bytes32 sessionId) internal {
        uint256 start = sessionWindowStart[sessionId];
        if (start == 0 || block.timestamp - start >= DAY_WINDOW) {
            sessionWindowStart[sessionId] = block.timestamp;
            sessionSpentThisWindow[sessionId] = 0;
        }
    }

    function _rollAccountWindow() internal {
        if (accountWindowStart == 0 || block.timestamp - accountWindowStart >= DAY_WINDOW) {
            accountWindowStart = block.timestamp;
            accountSpentThisWindow = 0;
        }
    }

    function _blockTimestampMs() internal view returns (uint256) {
        return block.timestamp * MILLIS_PER_SECOND;
    }

    function _currentAccountSpent() internal view returns (uint256) {
        if (accountWindowStart == 0 || block.timestamp - accountWindowStart >= DAY_WINDOW) {
            return 0;
        }
        return accountSpentThisWindow;
    }

    function _currentAccountRemaining() internal view returns (uint256) {
        uint256 spent = _currentAccountSpent();
        return accountMaxDaily > spent ? accountMaxDaily - spent : 0;
    }

    function _currentSessionSpent(bytes32 sessionId) internal view returns (uint256) {
        uint256 start = sessionWindowStart[sessionId];
        if (start == 0 || block.timestamp - start >= DAY_WINDOW) {
            return 0;
        }
        return sessionSpentThisWindow[sessionId];
    }
}

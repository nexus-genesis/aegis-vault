// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SmartAccount (Solidity) security test suite — Sprint 2
 * @notice On-chain mirror of the JS smart-account.test.js matrix (INV-002/003/
 *         005/006/007), PLUS the cross-language golden vectors shared with
 *         packages/chain-eth/test/canonical.test.js.
 *
 * GOLDEN fixture (fixed, non-random):
 *   FIXED_PRIVKEY = 0x11..11, GOLDEN_ADDR = its EVM address (cast-verified)
 *   GOLDEN_DIGEST = hashIntent over the golden intent (computed in JS by
 *                   chain-eth/canonical.js hashIntentDigest)
 *   GOLDEN_SIG    = 65-byte (r||s||v) signature over GOLDEN_DIGEST (produced
 *                   by chain-eth/canonical.js signIntentDigest)
 *
 * The golden tests prove the JS side and this contract agree byte-for-byte on
 * the canonical digest AND on the secp256k1 signature format (plain digest,
 * low-S, no EIP-191 prefix).
 */
import { Test } from "forge-std/Test.sol";
import { SmartAccount } from "../src/SmartAccount.sol";
import { DenyList } from "../src/DenyList.sol";

contract SmartAccountTest is Test {
    address internal constant OWNER = address(0x0Aa);
    address internal constant EMERGENCY = address(0x0Bb);

    // Fixed test-only key (32 bytes of 0x11) — matches chain-eth golden fixture.
    uint256 internal constant FIXED_PRIVKEY =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    // EVM address derived from FIXED_PRIVKEY (cast-verified).
    address internal constant GOLDEN_ADDR = 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A;

    bytes32 internal constant SESSION_ID =
        0xabababababababababababababababababababababababababababababababab;
    uint256 internal constant ISSUED_AT = 1700000000000;
    uint256 internal constant EXPIRES_AT = 1700003600000;

    // Cross-language golden values (computed by chain-eth/canonical.js).
    bytes32 internal constant GOLDEN_DIGEST =
        0x11bba5575092be0c71c18c01324410a66db47ff580ace0edc433b2a29104d740;
    bytes internal constant GOLDEN_SIG =
        hex"38715644a3619f2036d7b3db287f953b5b9e735663045f16bc34350f47633ea33a6e6d579aae7b9e711d78fca470cb71d8d93ae12f319f91d224b7bad65b9cfa1b";

    SmartAccount internal acct;
    SmartAccountHarness internal harness;

    // ── Setup ─────────────────────────────────────────────────────────────

    function setUp() public {
        acct = new SmartAccount(OWNER, EMERGENCY, 1_000_000);
        harness = new SmartAccountHarness(OWNER, EMERGENCY, 1_000_000);
        _registerGoldenSession(acct, SESSION_ID);
    }

    function _registerGoldenSession(SmartAccount a, bytes32 sid) internal {
        vm.prank(OWNER);
        a.registerSession(
            sid,
            "agent-1",
            GOLDEN_ADDR,
            ISSUED_AT,
            EXPIRES_AT,
            1000, // maxPerTx
            5000, // maxDaily
            _arr("ethereum"),
            _arr("USDC"),
            _arr("0xContract"),
            _arr("transfer"),
            _arr("0xRecipient")
        );
    }

    function _registerSession(
        SmartAccount a,
        bytes32 sid,
        uint256 maxPerTx,
        uint256 maxDaily
    ) internal {
        vm.prank(OWNER);
        a.registerSession(
            sid,
            "agent-1",
            GOLDEN_ADDR,
            ISSUED_AT,
            EXPIRES_AT,
            maxPerTx,
            maxDaily,
            _arr("ethereum"),
            _arr("USDC"),
            _arr("0xContract"),
            _arr("transfer"),
            _arr("0xRecipient")
        );
    }

    function _arr(string memory v) internal pure returns (string[] memory out) {
        out = new string[](1);
        out[0] = v;
    }

    // ── Intent / signature helpers ────────────────────────────────────────

    function _intentFor(
        bytes32 sid,
        uint256 amount,
        uint256 nonce
    ) internal pure returns (SmartAccount.IntentFields memory i) {
        i = SmartAccount.IntentFields({
            sessionId: sid,
            action: "transfer",
            chain: "ethereum",
            asset: "USDC",
            amount: amount,
            recipient: "0xRecipient",
            contractAddr: "0xContract",
            method: "transfer",
            nonce: nonce,
            agentId: "agent-1",
            sessionIssuedAt: ISSUED_AT,
            sessionExpiresAt: EXPIRES_AT
        });
    }

    function _intent(uint256 amount, uint256 nonce)
        internal
        pure
        returns (SmartAccount.IntentFields memory)
    {
        return _intentFor(SESSION_ID, amount, nonce);
    }

    /// Sign the intent's canonical digest with FIXED_PRIVKEY → (r||s||v).
    function _signIntent(SmartAccount a, SmartAccount.IntentFields memory intent)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = a.hashIntent(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(FIXED_PRIVKEY, digest);
        return abi.encodePacked(r, s, v);
    }

    // ── Cross-language golden vectors ─────────────────────────────────────

    function test_golden_hashIntent_matches_js_digest() public {
        assertEq(acct.hashIntent(_intent(100, 1)), GOLDEN_DIGEST);
    }

    function test_golden_signature_executes() public {
        // The 65-byte signature produced by the JS signIntentDigest must pass
        // the contract's ecrecover + all policies for the golden intent.
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_golden_sig_recovers_to_golden_addr() public view {
        (uint8 v, bytes32 r, bytes32 s) = _splitSig(GOLDEN_SIG);
        assertEq(ecrecover(GOLDEN_DIGEST, v, r, s), GOLDEN_ADDR);
    }

    function test_tampered_amount_rejected_INV002() public {
        // GOLDEN_SIG is bound to amount=100; any other amount changes the
        // digest and must fail the signature recovery.
        vm.expectRevert(SmartAccount.InvalidSignature.selector);
        acct.executeFromAgent(_intent(101, 1), GOLDEN_SIG);
    }

    // ── INV-002 amount binding ────────────────────────────────────────────

    function test_amount_is_part_of_digest_INV002() public view {
        assertTrue(acct.hashIntent(_intent(1, 1)) != acct.hashIntent(_intent(2, 1)));
    }

    // ── INV-003 bounded sessions ──────────────────────────────────────────

    function test_unregistered_session_rejected_INV003() public {
        SmartAccount.IntentFields memory i = _intent(100, 1);
        i.sessionId = bytes32(uint256(0));
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotRegistered.selector, bytes32(uint256(0))));
        acct.executeFromAgent(i, GOLDEN_SIG);
    }

    function test_revoked_session_rejected_INV003() public {
        vm.prank(OWNER);
        acct.revokeSession(SESSION_ID);
        vm.expectRevert(SmartAccount.SessionRevokedError.selector);
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_expired_session_rejected_INV003() public {
        vm.warp(EXPIRES_AT + 1);
        vm.expectRevert(SmartAccount.SessionExpired.selector);
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_expired_session_rejected_when_warped_in_seconds_INV003() public {
        // Regression for the ms/seconds boundary: session timestamps are ms
        // epoch values in the canonical schema, while block.timestamp is in
        // seconds. The contract must convert block time to ms before checking
        // expiry, otherwise sessions would live ~1000x too long on-chain.
        vm.warp((EXPIRES_AT / 1000) + 1);
        vm.expectRevert(SmartAccount.SessionExpired.selector);
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_session_bound_fields_mismatch_INV003() public {
        SmartAccount.IntentFields memory i = _intent(100, 1);
        i.agentId = "evil-agent";
        vm.expectRevert(SmartAccount.InvalidSession.selector);
        acct.executeFromAgent(i, GOLDEN_SIG);
    }

    function test_whitelist_violation_INV003() public {
        SmartAccount.IntentFields memory i = _intent(100, 1);
        i.chain = "bitcoin";
        bytes memory sig = _signIntent(acct, i); // hoisted: no external call between expectRevert and target
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.WhitelistViolation.selector, "chain"));
        acct.executeFromAgent(i, sig);
    }

    // ── INV-005 no self-escalation / INV-007 allowance surface ───────────

    function test_self_escalation_action_rejected_INV005() public {
        // A genuine self-escalation action (raises limits) is rejected even
        // with a valid signature (INV-005).
        SmartAccount.IntentFields memory i = _intent(100, 1);
        i.action = "increaseLimit";
        bytes memory sig = _signIntent(acct, i);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.SelfEscalationRejected.selector, "increaseLimit"));
        acct.executeFromAgent(i, sig);
    }

    function test_self_escalation_method_rejected_INV005() public {
        // Self-escalation via the METHOD dimension.
        SmartAccount.IntentFields memory i = _intent(100, 1);
        i.method = "addOwner";
        bytes memory sig = _signIntent(acct, i);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.SelfEscalationRejected.selector, "transfer"));
        acct.executeFromAgent(i, sig);
    }

    function test_allowance_surface_rejected_INV007() public {
        // Allowance-surface actions (out-of-band spend, INV-007) are rejected
        // with the dedicated error even if whitelisted. Covers the Sprint 2
        // HIGH finding: the previous deny list missed these variants.
        string[7] memory actions = [
            "approve", "approve_and_call", "create_allowance", "permit",
            "setApprovalForAll", "transferFrom", "increaseapproval"
        ];
        for (uint256 k = 0; k < actions.length; k++) {
            SmartAccount.IntentFields memory i = _intent(100, k + 1);
            i.action = actions[k];
            bytes memory sig = _signIntent(acct, i);
            vm.expectRevert(abi.encodeWithSelector(SmartAccount.AllowanceSurfaceRejected.selector, actions[k]));
            acct.executeFromAgent(i, sig);
        }
    }

    function test_allowance_surface_method_rejected_INV007() public {
        SmartAccount.IntentFields memory i = _intent(100, 1);
        i.method = "setApprovalForAll";
        bytes memory sig = _signIntent(acct, i);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.AllowanceSurfaceRejected.selector, "transfer"));
        acct.executeFromAgent(i, sig);
    }

    function test_owner_only_register_INV005() public {
        bytes32 sid = bytes32(uint256(0xee));
        vm.prank(GOLDEN_ADDR); // a non-owner agent must not self-register
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotOwner.selector, GOLDEN_ADDR));
        acct.registerSession(
            sid, "agent-evil", GOLDEN_ADDR, ISSUED_AT, EXPIRES_AT, 100, 100,
            _arr("ethereum"), _arr("USDC"), _arr("0xContract"), _arr("transfer"), _arr("0xRecipient")
        );
    }

    // ── INV-006 emergency brake-only ──────────────────────────────────────

    function test_pause_emergency_only_INV006() public {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotEmergency.selector, OWNER));
        acct.pause();
        vm.prank(EMERGENCY);
        acct.pause();
        assertTrue(acct.paused());
        // A valid signature cannot execute while paused.
        vm.expectRevert(SmartAccount.AccountPaused.selector);
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_resume_owner_only_INV006() public {
        vm.prank(EMERGENCY);
        acct.pause();
        vm.prank(EMERGENCY);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotOwner.selector, EMERGENCY));
        acct.resume();
        vm.prank(OWNER);
        acct.resume();
        assertFalse(acct.paused());
    }

    function test_freeze_emergency_only_INV006() public {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotEmergency.selector, OWNER));
        acct.freeze();
        vm.prank(EMERGENCY);
        acct.freeze();
        assertTrue(acct.frozen());
        vm.expectRevert(SmartAccount.AccountFrozen.selector);
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_emergency_reduce_only_INV006() public {
        // Emergency may only LOWER ceilings — raising must be rejected.
        vm.prank(EMERGENCY);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.SelfEscalationRejected.selector, "raise-limit"));
        acct.emergencyReduceLimit(SESSION_ID, 5000, 5000);
        vm.prank(EMERGENCY);
        acct.emergencyReduceLimit(SESSION_ID, 100, 100);
        assertEq(acct.sessionMaxLoss(SESSION_ID), 100);
    }

    // ── INV-007 bounded blast radius ──────────────────────────────────────

    function test_per_tx_ceiling_INV007() public {
        SmartAccount.IntentFields memory i = _intent(5000, 1); // > maxPerTx=1000
        bytes memory sig = _signIntent(acct, i);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.AmountExceedsPerTx.selector, 1000));
        acct.executeFromAgent(i, sig);
    }

    function test_session_cumulative_ceiling_INV007() public {
        bytes32 sid = bytes32(uint256(0xcdcd));
        _registerSession(acct, sid, 1000, 150);
        SmartAccount.IntentFields memory i1 = _intentFor(sid, 100, 1);
        acct.executeFromAgent(i1, _signIntent(acct, i1));
        SmartAccount.IntentFields memory i2 = _intentFor(sid, 100, 2);
        bytes memory sig2 = _signIntent(acct, i2);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.AmountExceedsDaily.selector, 150));
        acct.executeFromAgent(i2, sig2);
    }

    function test_account_cumulative_ceiling_INV007() public {
        // Fresh account with a tight account-wide ceiling (INV-007, mirror of
        // the JS engine's account policy bound).
        SmartAccount tight = new SmartAccount(OWNER, EMERGENCY, 150);
        bytes32 sid = bytes32(uint256(0xefef));
        _registerSession(tight, sid, 1000, 5000);
        SmartAccount.IntentFields memory i1 = _intentFor(sid, 100, 1);
        tight.executeFromAgent(i1, _signIntent(tight, i1));
        SmartAccount.IntentFields memory i2 = _intentFor(sid, 60, 2);
        bytes memory sig2 = _signIntent(tight, i2);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.AmountExceedsDaily.selector, 150));
        tight.executeFromAgent(i2, sig2);
    }

    function test_nonce_replay_rejected_INV007() public {
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.BadNonce.selector, 2, 1));
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_nonce_must_increase_INV007() public {
        SmartAccount.IntentFields memory i2 = _intent(100, 2);
        acct.executeFromAgent(i2, _signIntent(acct, i2));
        // nonce regresses 2 → 1 → rejected
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.BadNonce.selector, 3, 1));
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
    }

    function test_register_requires_ceilings_INV007() public {
        bytes32 sid = bytes32(uint256(0xdd));
        vm.prank(OWNER);
        vm.expectRevert(SmartAccount.InvalidSession.selector);
        acct.registerSession(
            sid, "agent-1", GOLDEN_ADDR, ISSUED_AT, EXPIRES_AT, 0, 0,
            _arr("ethereum"), _arr("USDC"), _arr("0xContract"), _arr("transfer"), _arr("0xRecipient")
        );
    }

    function test_estimate_max_loss_INV007() public {
        assertEq(acct.estimateMaxLoss(), 1_000_000);
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
        assertEq(acct.estimateMaxLoss(), 1_000_000 - 100);
    }

    function test_session_max_loss_tracks_current_remaining_INV007() public {
        // session maxDaily = 5000 (see _registerGoldenSession). maxPerTx (1000)
        // does NOT cap the cumulative-window loss — like the JS engine, a
        // session may issue many per-tx-sized executions until the daily
        // ceiling binds (mirrors smart-account.js estimateMaxLoss).
        assertEq(acct.sessionMaxLoss(SESSION_ID), 5000);
        acct.executeFromAgent(_intent(100, 1), GOLDEN_SIG);
        assertEq(acct.sessionMaxLoss(SESSION_ID), 4900);
    }

    // ── DenyList: fixture parity + normalization matrix (Sprint 2 fix) ───

    function test_deny_list_fixture_all_entries_rejected() public {
        // Every entry the JS engine rejects (scripts/sync-deny-list.mjs →
        // testdata/deny-actions.json) must be rejected on-chain too.
        string memory root = vm.projectRoot();
        string memory json = vm.readFile(string.concat(root, "/testdata/deny-actions.json"));
        string[] memory selfEsc = abi.decode(vm.parseJson(json, ".self_escalation"), (string[]));
        string[] memory allowance = abi.decode(vm.parseJson(json, ".allowance_surface"), (string[]));
        for (uint256 i = 0; i < selfEsc.length; i++) {
            assertTrue(harness.isEscalationForTest(selfEsc[i], ""), string.concat("self-escalation entry not rejected: ", selfEsc[i]));
        }
        for (uint256 i = 0; i < allowance.length; i++) {
            assertTrue(harness.isAllowanceSurfaceForTest(allowance[i], ""), string.concat("allowance-surface entry not rejected: ", allowance[i]));
        }
    }

    function test_deny_list_normalization_variants() public {
        // Casing / separator variants of deny actions must be caught — the
        // on-chain normalizer mirrors JS normalizeAction (INV-005/007).
        assertTrue(harness.isEscalationForTest("INCREASE_LIMIT", ""));
        assertTrue(harness.isEscalationForTest("IncreaseLimit", ""));
        assertTrue(harness.isEscalationForTest("increase limit", ""));
        assertTrue(harness.isEscalationForTest("ADD_OWNER", ""));
        assertTrue(harness.isEscalationForTest("grant-Role", ""));
        assertTrue(harness.isEscalationForTest("set_implementation_code", ""));
        assertTrue(harness.isEscalationForTest("upgrade_and_call", ""));
        assertTrue(harness.isAllowanceSurfaceForTest("APPROVE", ""));
        assertTrue(harness.isAllowanceSurfaceForTest("approve_and_call", ""));
        assertTrue(harness.isAllowanceSurfaceForTest("ApproveAndCall", ""));
        assertTrue(harness.isAllowanceSurfaceForTest("set-approval-for-all", ""));
        assertTrue(harness.isAllowanceSurfaceForTest("create_allowance", ""));
        // method-level variants
        assertTrue(harness.isEscalationForTest("transfer", "addOwner"));
        assertTrue(harness.isEscalationForTest("transfer", "grant-role"));
        assertTrue(harness.isAllowanceSurfaceForTest("transfer", "setApprovalForAll"));
        // benign controls must NOT be flagged
        assertFalse(harness.isEscalationForTest("transfer", "transfer"));
        assertFalse(harness.isAllowanceSurfaceForTest("transfer", "transfer"));
        assertFalse(harness.isEscalationForTest("swap", "transfer"));
    }

    function test_decrease_allowance_not_denied_Q4() public {
        // Q4: decreaseAllowance REDUCES allowance — it is neither a
        // self-escalation nor an allowance-surface grant, so it must not be
        // in the deny list (misclassification would block legitimate
        // hardening ops and invite a future bypass patch).
        assertFalse(harness.isEscalationForTest("decreaseAllowance", ""));
        assertFalse(harness.isAllowanceSurfaceForTest("decreaseAllowance", ""));
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    function _splitSig(bytes memory sig)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65, "sig must be 65 bytes");
        // bytes memory layout: [32] length, [32..64] r, [64..96] s, [96] v.
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * Test harness exposing the SmartAccount's internal deny checks so the suite
 * can assert on the normalized reject surface directly (no signature needed).
 */
contract SmartAccountHarness is SmartAccount {
    constructor(address _owner, address _emergency, uint256 _ceiling)
        SmartAccount(_owner, _emergency, _ceiling)
    {}

    function isEscalationForTest(string calldata action, string calldata method) external pure returns (bool) {
        return _isSelfEscalation(action, method);
    }

    function isAllowanceSurfaceForTest(string calldata action, string calldata method) external pure returns (bool) {
        return _touchesAllowanceSurface(action, method);
    }
}

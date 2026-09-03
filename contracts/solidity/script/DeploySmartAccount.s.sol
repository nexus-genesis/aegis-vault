// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { SmartAccount } from "../src/SmartAccount.sol";

/**
 * @title DeploySmartAccount — deployment script (Sprint 2.3)
 * @notice Deploys the SmartAccount hard-policy contract. Used for on-chain
 *         E2E: anvil/local chain or a real testnet.
 *
 * Usage (see foundry.toml [rpc_endpoints] for named networks):
 *   forge script script/DeploySmartAccount.s.sol:DeploySmartAccount \
 *       --rpc-url <rpc_url> --broadcast --private-key <owner_pk>
 *
 * Constructor args are read from the environment so the same script works on
 * any network:
 *   OWNER_ADDR  (required, must own the account on-chain)
 *   EMERGENCY_ADDR (required, brake-only key)
 *   ACCOUNT_MAX_DAILY (default 1_000_000)
 */
contract DeploySmartAccount is Script {
    function run() external returns (SmartAccount deployed) {
        address owner = vm.envAddress("OWNER_ADDR");
        address emergency = vm.envAddress("EMERGENCY_ADDR");
        uint256 accountMaxDaily = vm.envOr("ACCOUNT_MAX_DAILY", uint256(1_000_000));

        vm.startBroadcast();
        deployed = new SmartAccount(owner, emergency, accountMaxDaily);
        vm.stopBroadcast();

        console2.log("SmartAccount deployed at:", address(deployed));
        console2.log("  owner:", owner);
        console2.log("  emergencyKey:", emergency);
        console2.log("  accountMaxDaily:", accountMaxDaily);
    }
}

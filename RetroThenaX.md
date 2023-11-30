## Vulnerability disclosure
On October 4th, few hours before heading to the airport for a vacation, I decided to hunt for bugs. 2 hours before heading out, I found a high within Retro and Thena which would allow for an arbitrary user to steal all of the rewards for the upcoming weeks. There was also a third project vulnerable, which I cannot name publicly, which I will further refer to as protocol X. X was the only one to pay out a bounty.

### Summary
- 1 Hour after discovering the vulnerability I managed to successfully submit it to X with a full working PoC. 
- After valuating the issue, X awarded me with their respective bug bounty reward for High Severity Issues
- Considering I didn't have enough time (as I was heading to the airport) to rewrite the PoC to suit the contracts of Retro and Thena, I decided to still contact them and inform them of the issue even without a clear PoC written in Foundry.
- Unfortunately Retro were unprofessional and immediately denied having any vulnerabilities within their code (yes, they *actually* claimed their code didnt contain any bugs). Both projects demanded a PoC to validate the issue. 
- As I was on a vacation, I had decided I will not do anything work-related. Considering the vulnerability had been present for months and the team was informed, the PoC did not seem urgent at that time. 
- Despite everything, the next day (October 5th) I decided to redo the PoC while on vacation and send it to both Retro and Thena. Both teams claimed they had already caught it themselves, hence why no bounty would be issued. It is worth noting Thena had in fact pushed a hotfix 6 hours prior to me sending the PoC. 
- It's impossible to know whether both projects would've caught the issue if it wasn't for my earlier messages. I genuinely want to believe it was just unfortunate timing. Though, one thing is sure - both projects did not take the situation seriously enough.


### What exactly the projects consist of
All 3 projects consist of Curve's famous Voting Escrow (ve). People lock the project's token and based on the duration of the lock, they're allocated voting power. The ownership of the lock is stored in the way of an ERC721 (NFT). Every week users can vote for a gauge. When they vote for it, they 'deposit' the voting power into the gauge's bribes. After rewards are distributed, based on their balance within the bribe contracts, the users are allocated their cut of the rewards.

### Vulnerability detail
In order to understand the vulnerability we need to first take a look at the `vote` function
```solidity
    function _vote(uint256 _tokenId, address[] memory _poolVote, uint256[] memory _weights) internal {
        _reset(_tokenId);
        uint256 _poolCnt = _poolVote.length;
        uint256 _weight = IVotingEscrow(_ve).balanceOfNFT(_tokenId);
        uint256 _totalVoteWeight = 0;
        uint256 _totalWeight = 0;
        uint256 _usedWeight = 0;
        uint256 _time = _epochTimestamp();



        for (uint i = 0; i < _poolCnt; i++) {

            if(isAlive[gauges[_poolVote[i]]]) _totalVoteWeight += _weights[i];
        }

        for (uint256 i = 0; i < _poolCnt; i++) {
            address _pool = _poolVote[i];
            address _gauge = gauges[_pool];

            if (isGauge[_gauge] && isAlive[_gauge]) {
                uint256 _poolWeight = _weights[i] * _weight / _totalVoteWeight;

                require(votes[_tokenId][_pool] == 0);
                require(_poolWeight != 0);

                poolVote[_tokenId].push(_pool);
                weightsPerEpoch[_time][_pool] += _poolWeight;

                votes[_tokenId][_pool] += _poolWeight;

                IBribe(internal_bribes[_gauge]).deposit(uint256(_poolWeight), _tokenId);
                IBribe(external_bribes[_gauge]).deposit(uint256(_poolWeight), _tokenId);
                
                _usedWeight += _poolWeight;
                _totalWeight += _poolWeight;
                emit Voted(msg.sender, _tokenId, _poolWeight);
            }
        }
        if (_usedWeight > 0) IVotingEscrow(_ve).voting(_tokenId);
        totalWeightsPerEpoch[_time] += _totalWeight;
    }
```
```solidity
    function _reset(uint256 _tokenId) internal {
        address[] storage _poolVote = poolVote[_tokenId];
        uint256 _poolVoteCnt = _poolVote.length;
        uint256 _totalWeight = 0;
        uint256 _time = _epochTimestamp();

        for (uint256 i = 0; i < _poolVoteCnt; i ++) {
            address _pool = _poolVote[i];
            uint256 _votes = votes[_tokenId][_pool];

            if (_votes != 0) {

                // if user last vote is < than epochTimestamp then votes are 0! IF not underflow occur
                if(lastVoted[_tokenId] > _time) weightsPerEpoch[_time][_pool] -= _votes;

                votes[_tokenId][_pool] -= _votes;
                
                IBribe(internal_bribes[gauges[_pool]]).withdraw(uint256(_votes), _tokenId);
                IBribe(external_bribes[gauges[_pool]]).withdraw(uint256(_votes), _tokenId);

                // if is alive remove _votes, else don't because we already done it in killGauge()
                if(isAlive[gauges[_pool]]) _totalWeight += _votes;
                
                emit Abstained(_tokenId, _votes);
            }
        }
```

To summarize it - anytime `vote` is invoked, it first makes a call to `reset`, withdrawing all current votes from the corresponding bribes. After votes are successfully reset, the user 'deposits' into the bribes of the gauges they're voting for. 
So far so good. However, let's take a look at the bribe's `withdraw` function 
```solidity
    function withdraw(uint256 amount, uint256 tokenId) external nonReentrant {
        require(amount > 0, "Cannot withdraw 0");
        require(msg.sender == voter);
        uint256 _startTimestamp = IMinter(minter).active_period(); 
        address _owner = IVotingEscrow(ve).ownerOf(tokenId);

        // incase of bribe contract reset in gauge proxy
        if (amount <= _balances[_owner][_startTimestamp]) {
            uint256 _oldSupply = _totalSupply[_startTimestamp]; 
            uint256 _oldBalance = _balances[_owner][_startTimestamp];
            _totalSupply[_startTimestamp] =  _oldSupply - amount;
            _balances[_owner][_startTimestamp] =  _oldBalance - amount;
            emit Withdrawn(tokenId, amount);
        }

    }
```
I believe 90% of auditors looking at this code will immediately see that something seems weird. If the amount we're trying to withdraw is larger than the user's balance, the user's balance is not reduced. But how do we reach such state?

Well, we actually reach such state quite easily. Balances are specific for the week. So everytime a new week starts, the user's balance is set to 0. This means that every time a new week starts and the user calls `vote`, the call to `reset` actually does nothing within the bribe contracts. The user's balance is 0 and when we try to 'withdraw' any amount, we actually don't do anything and the balance remains 0. After `vote` executes (with the `deposit` towards the bribe) the balance is correctly set. So far there's no impact right? Everything just behaves weirdly? And in fact if we try to `vote` with the same NFT again within the same week evertything will work as expected.

#### Ok, but how do we exploit this?
Well, this is the interesting part.

Note: even Retro and Thena when finding the issue themselves, did not manage to find this impact. All they found was how it could result in an innocent user getting less rewards than expected if they tried to vote with multiple NFTs in a specific order within the same week. They couldn't figure out how an adversary could utilize it to steal all rewards for the week and it potentially happening unnoticed.

So here's the attack path: 
1. User mints lock for dust amounts. (let's say `1 wei`) One for every added gauge within the project.
2. User votes 1 NFT to every different gauge. 
3. User creates a lock for a relatively high amount of tokens. (let's say `1000e18`)
4. A week passes. The user's balance in each gauge is now 0.
5. User votes with the high-value NFT for the first gauge. His balance there is now equivalent to this NFT's balance (`1000e18`)
6. User calls vote.reset for the low-value NFT at the same (first) gauge. His balance is then equal to the `high-value NFT's - low-value NFT's` (`1000e18 - 1 wei`)
7. User calls vote.reset on the high-value NFT. Since its value is lower than the current balance of the user, the user's balance will not be reduced. (`1000e18 - 1 wei < 1000e18`)
8. Repeat steps 5-7 for all available gauges

In the end the user has not voted with any of the NFT's. Despite this, the user has a balance in all gauges. The user can then send the high-value NFT to his other wallet, where he has such low-value NFTs set from last week and repeat this attack endlessly. In the end, the user can have an arbitrary high balance in all bribes, therefore getting all of the rewards for themselves. Furthermore, since the balance will be spread out across multiple wallets and none of them will have a suspiciously high balance, this could go unnoticed for long time.

#### Proof-Of-Concept
You can check the PoC [here](https://gist.github.com/deadrosesxyz/7b2407529757a392945a60c57b0148db)


### Impact
Adversary can steal all rewards allocated for the upcoming week. Under some conditions and assumptions, this could potentially remain unnoticed for a prolonged time frame.

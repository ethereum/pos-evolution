# Evolution of the Ethereum Proof-of-Stake Consensus Protocol

[Luca Zanolini](https://twitter.com/luca_zanolini)

In this document we present the evolution of the proof-of-stake consensus protocol of Ethereum, called **Gasper**, aiming at a self-contained reference for future study and research. 

<details><summary>Implementation</summary>
    
    We include in boxes of this kind the (explained) implementation of the most relevant theoretical parts. Observe that the code showed for the implementation follows the [consensus pyspec](https://github.com/ethereum/consensus-specs), and is presented using Simple Serialize (SSZ), a serialization and merkleization standard created specifically for Ethereum consensus. This specification serves as a reference for consensus layer devs and is also used for creating the test case vectors for client teams. A tutorial on how to run the Ethereum consensus pyspec can be found [here](https://archive.devcon.org/archive/watch/6/how-to-use-executable-consensus-pyspec/?tab=YouTube), and an updated annotated specification can be found [here](https://eth2book.info/bellatrix/part3/).
    
   </details>


#### Disclaimer 

Since this document aims at grouping together all the most relevant resources concerning the proof-of-stake consensus protocol of Ethereum, some parts are just imported as they are in the original source. If this is the case, the text will be in *italic type* and the original reference is given.

#### Acknowledgments  

Special thanks to Ittai Abraham, Aditya Asgaonkar, Francesco D'Amato, Tyler Holmes, and anonymous reviewers for feedback and helpful discussions.

The proof-of-stake consensus protocol of Ethereum, Gasper, evolved during the years. This is because attacks were found that undermined its properties and functioning. As a response to that, solutions were developed to cope with the problems. 

In order to better understand the current implemented protocol, we start by presenting the [original version of it](https://arxiv.org/pdf/2003.03052.pdf), by Buterin *et al.*, highlighting its underlying components and properties. Then, we present the most relevant attacks and/or problems that have been discovered so far, and discuss solutions to them.

First, let us introduce the system model that will be used from now on.

### System Model

#### Validators

We consider a system of $n$ *validators* $\mathcal{V} = \{v_1, \dots, v_n\}$ that communicate with each other through exchanging messages. Every validator is identified by a unique cryptographic identity and the public keys are common knowledge.


<details><summary>Validator</summary>
    
```python
class Validator(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32  # Commitment to pubkey for withdrawals
    effective_balance: Gwei  # Balance at stake
    slashed: boolean
    # Status epochs
    activation_eligibility_epoch: Epoch  # When criteria for activation were met
    activation_epoch: Epoch
    exit_epoch: Epoch
    withdrawable_epoch: Epoch  # When validator can withdraw funds
```

This object contains all the information relating to a particular validator $v_i \in \mathcal{V}$. In particular:

`pubkey`: public key for signing;

`withdrawal_credentials`: a hash of the pubkey that will be used to withdraw;

`effective_balance`: the balance of the validator that is used for all calculations;

`slashed`: it says if the validator has been *slashed* (this term will be introduced few sections below);

`activation_eligibility_epoch`: when the validator became eligible for activation, i.e., when it became eligible to become an active validator;

`activation_epoch`: when the validator was activated;

`exit_epoch`: when the validator exited from $\mathcal{V}$, voluntarily or not;

`withdrawable_epoch`: when the validator became eligible to withdraw their balance;

The precise epochs are kept around in order to calculate the current active validator set and the historical active validator set.


Observe that validators have two private/public key pairs: `pubkey`, used for signing protocol messages, and a separate *withdrawal key*. `withdrawal_credentials` is  obtained from the validator's withdrawal key and it allows a validator to prove it owns the funds enabling it to withdraw them. 
    
   </details>



Validators are assigned a protocol to follow.
A protocol for $\mathcal{V}$ consists of a collection of programs with instructions for all validators.

Each validator has a deposit (or *stake*); when a validator joins $\mathcal{V}$, its deposit is the number of deposited coins, e.g., ETH. After joining, each validator’s balance rises and falls with rewards and penalties.


<details><summary>Deposit</summary>

```python
class DepositMessage(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
```

```python
class DepositData(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
    signature: BLSSignature  # Signing over DepositMessage
```

Observe that, as a rule, there can only be one validator $v_i$ for each `pubkey`; if `pubkey` is already present in the list of validators, then `amount` is added to $v_i$'s balance. Otherwise, a new entry $v_i$ is appended to the list and credited with amount.

Requiring the `withdrawal_credentials` and the `amount` to be signed by the public key prevents some vectors of attack. This is why we have `DepositData(Container)`, i.e., a signed `DepositMessage(Container)`.

A proof that a validator deposited is given by the following object.

```python
class Deposit(Container):
    proof: Vector[Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH + 1]  # Merkle path to deposit root
    data: DepositData
```

Every validator has an `effective_balance` (of at most 32 ETH), and its voting power is weighted by it. Any balance above this is ignored. 

However, validator balances are stored, for efficiency reasons, in *two* places: (i) in the `effective_balance` in the `Validator` record and (ii) in the (exact) `balances` in a separate record (in `BeaconState`, see few sections below).

*The exact balances change every epoch (due to rewards and penalties), so we store them in a compact array that requires rehashing only <32 MB to update, while the effective balances (which are used for all other computations that require validator balances) are updated using a hysteresis formula: if the effective balance is $n$ ETH, and if the exact balance goes below $n-0.25$ ETH, then the effective balance is set to $n-1$ ETH, and if the exact balance goes above $n+1.25$ ETH the effective balance is set to $n+1$ ETH.* 

*Since the exact balance must change by at least a full $0.5$ ETH to trigger an effective balance update, this ensures an attacker can't make effective balances update every epoch -- and thus cause processing the chain to become very slow -- by repeatedly nudging the exact balances above, and then below, some threshold.* [https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md]

This effective balances are update according to the following function.


```python
def process_effective_balance_updates(state: BeaconState) -> None:
    # Update effective balances with hysteresis
    for index, validator in enumerate(state.validators):
        balance = state.balances[index]
        HYSTERESIS_INCREMENT = uint64(EFFECTIVE_BALANCE_INCREMENT // HYSTERESIS_QUOTIENT)
        DOWNWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER
        UPWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER
        if (
            balance + DOWNWARD_THRESHOLD < validator.effective_balance
            or validator.effective_balance + UPWARD_THRESHOLD < balance
        ):
            validator.effective_balance = min(balance - balance % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)
```

Finally, deposits are processed through the following function.

```python
def process_deposit(state: BeaconState, deposit: Deposit) -> None:
    # Verify the Merkle branch
    assert is_valid_merkle_branch(
        leaf=hash_tree_root(deposit.data),
        branch=deposit.proof,
        depth=DEPOSIT_CONTRACT_TREE_DEPTH + 1,  # Add 1 for the List length mix-in
        index=state.eth1_deposit_index,
        root=state.eth1_data.deposit_root,
    )

    # Deposits must be processed in order
    state.eth1_deposit_index += 1

    pubkey = deposit.data.pubkey
    amount = deposit.data.amount
    validator_pubkeys = [validator.pubkey for validator in state.validators]
    if pubkey not in validator_pubkeys:
        # Verify the deposit signature (proof of possession) which is not checked by the deposit contract
        deposit_message = DepositMessage(
            pubkey=deposit.data.pubkey,
            withdrawal_credentials=deposit.data.withdrawal_credentials,
            amount=deposit.data.amount,
        )
        domain = compute_domain(DOMAIN_DEPOSIT)  # Fork-agnostic domain since deposits are valid across forks
        signing_root = compute_signing_root(deposit_message, domain)
        # Initialize validator if the deposit signature is valid
        if bls.Verify(pubkey, signing_root, deposit.data.signature):
            state.validators.append(get_validator_from_deposit(state, deposit))
            state.balances.append(amount)
            state.previous_epoch_participation.append(ParticipationFlags(0b0000_0000))
            state.current_epoch_participation.append(ParticipationFlags(0b0000_0000))
            state.inactivity_scores.append(uint64(0))
    else:
        # Increase balance by deposit amount
        index = ValidatorIndex(validator_pubkeys.index(pubkey))
        increase_balance(state, index, amount)
```

`BeaconState` will be preseted few sections below.

    
</details>


#### Failures

A validator that follows its protocol during an execution is called *honest*. On the other hand, a faulty validator may crash or even deviate arbitrarily from its specification, e.g., when corrupted by an adversary; such validators are also called *Byzantine*. In particular, Byzantine processes can *equivocate*, i.e., they can send conflicting messages. We consider Byzantine faults here and assume the existence of a probabilistic poly-time adversary $\mathcal{A}$ that can choose up to $f$ validators to corrupt. The adversary $\mathcal{A}$ knows the internal state of corrupted validators. Finally, we assume that the majority of the validators is honest.

#### Links

We assume that a best-effort gossip primitive that will reach all validators is available. Moreover, we assume that messages from honest validator to honest validator are eventually received and cannot be forged. This includes messages sent by Byzantine validators, once they have been received by some honest validator $v_i$ and gossiped around by $v_i$.

#### Time and sleepiness

Time is divided into discrete *slots* and a collection of $C$ slots forms an *epoch*. The genesis block $B_{\text{genesis}}$, i.e., the first block in the blockchain, has slot number $0$ and is the first block of epoch $0$. Generally, blocks belonging to epoch $j$ have slot numbers $jC + k$ as $k$ runs through $\{0, 1, \ldots , C − 1\}$. The adversary $\mathcal{A}$ can decide for each slot which honest validator is *awake* or *asleep* at that slot. Asleep validators do not execute the protocol and messages for that slot are queued and delivered in the first slot in which the validator is awake again. [https://eprint.iacr.org/2016/918.pdf]
Communication is asynchronous until a global stabilization time (GST), after which communication becomes synchronous, i.e., message delays and processing times are bounded by $\Delta$ and validators have synchronized clocks. Moreover, honest nodes sleep and wake up until a global awake time (GAT), after which all nodes are awake. Adversary nodes are always awake. [https://arxiv.org/pdf/2009.04987.pdf]


### Gasper

**Gasper** is a proof-of-stake consensus protocol obtained by the combination of two modules: **FFG Casper**, a finality gadget, and (a variation of) **LMD-GHOST**, a fork choice rule. The latter evolved during the years, due to some problems. 

#### Friendly Finality Gadget (FFG) Casper

**FFG Casper** is a partial consensus protocol atop a proposal mechanism, i.e., a mechanism which proposes blocks, that aims at *finalizing* these blocks. Once a block is finalized it cannot be reverted, and a conflicting finalized block cannot be obtained. Casper introduces *accountability*, i.e., if a validators violates some rule, it is possible to detect the violation and know which validator violated the rule. Accountability allows the system to penalize (to *slash*) Byzantine validators, solving the *nothing at stake* problem. 
Moreover, Casper introduces a way for the validator set to change over time, allowing new validators to join the validator set, and existing validators to leave.

[Casper](https://arxiv.org/pdf/1710.09437.pdf), introduced by Buterin and Griffith, works following a two-phase traditional propose-and-vote-based Byzantine fault tolerant (BFT) mechanism, such as [PBFT](https://pmg.csail.mit.edu/papers/osdi99.pdf) or [HotStuff](https://arxiv.org/pdf/1803.05069.pdf). Differently from PBFT or HotStuff, Casper is not a fully-specified protocol and is designed to be a *gadget* that works on top of a provided blockchain protocol. Again, differently from PBFT or HotStuff, in Casper there is no leader in charge of assembling proposals which are instead generated across honest nodes by an underlying proposal mechanism which produces child blocks of existing blocks, forming an ever-growing *block-tree*. The root of the three is the genesis block $B_{\text{genesis}}$. Casper only considers a subtree of the blocks generated by the proposal mechanism, which we call a *checkpoint tree*. Blocks in the Casper checkpoint tree are called *checkpoints*.


<details><summary>Checkpoint</summary>
    
```python
class Checkpoint(Container):
    epoch: Epoch
    root: Root
```
    
</details>




The genesis block is *justified* and *finalized*, according to the following description.

Casper proceeds as follows. Validators participate in the protocol by casting *votes* on blocks in the block-tree formed by the underlying proposal mechanism.  

A vote message consists of four fields: two blocks (called in the context of Casper, checkpoints) $s$ (source) and $t$ (target) together with their heights $h(s)$ and $h(t)$ (*The height $h(c)$ of a checkpoint $c$ is the number of elements in the checkpoint tree from $c$ (non-inclusive) to the root along the parent links.*). It is required to $s$ to be an ancestor of $t$ in the checkpoint tree, otherwise the vote is considered invalid. If $v_i$ is not in the validator set $\mathcal{V}$, the vote is considered invalid. Together with the signature of the validator $v_i$, a vote is expressed in the form $⟨v_i, s, t, h(s), h(t)⟩$.

*For the rest of this document, when we say “$\frac{2}{3}$ of validators”, we are referring to the deposit-weighted fraction; that is, a set of validators whose sum deposit size equals to $\frac{2}{3}$ of the total deposit size of the entire set of validators.*

Once a vote $⟨v_i, a, b, h(a), h(b)⟩$ has been cast by $\frac{2}{3}$ of validators and the checkpoint $a$ is justified (and the notion of *supermajority link* is defined as an ordered pair $(a,b),$ such that $\frac{2}{3}$ of validators have broadcast votes with source $a$ and target $b$), the checkpoint $b$ becomes justified. Finally, the checkpoint $b$ is finalized if $b$ is justified and at least $\frac{2}{3}$ of validators broadcast a vote $⟨v_i, b, c, h(b), h(c)⟩$, with $h(c)=h(b)+1.$ Observe that votes can skip checkpoints, i.e., given a vote $⟨v_i, a, b, h(a), h(b)⟩$, it is permitted to have $h(b) > h(a) + 1$.

Let $⟨v_i, s_1, t_1, h(s_1), h(t_1)⟩$ and $⟨v, s_2, t_2, h(s_2), h(t_2)⟩$ be two voted cast by validator $v_i$. Then, it must not be that either:

* $h(t_1) = h(t_2)$, i.e., a validator must not publish two distinct votes for the same target height; or
* $h(s_1) < h(s_2) < h(t_2) < h(t_1)$, i.e., a validator must not vote within the span of its other votes.

If a validator violates either (slashing) condition, the evidence of the violation can be observed, at which point the validator’s entire deposit is taken away (it is slashed) with a reward given to the submitter of the evidence transaction.

Casper satisfies the following two properties, and the proof can be found in the [full paper](https://arxiv.org/pdf/1710.09437.pdf).

* **Accountable Safety**: Two conflicting checkpoints cannot both be finalized, provided that less than $\frac{1}{3}$ of the total deposit size of the entire set of validators is adversarial. Moreover, two conflicting checkpoints imply more than $\frac{1}{3}$ adversarial stake can be detected.
* **Plausible Liveness**: It is always possible to produce new finalized checkpoints, provided there exist blocks extending the justified checkpoint with the greatest height, and more than $\frac{2}{3}$ of the validators' stake is honest.

As mentioned above, the set of validators needs to be able to change. New validators must be able to join, and existing validators must be able to leave. 


<details><summary>Voluntary Exit</summary>
    
```python
class VoluntaryExit(Container):
    epoch: Epoch  # Earliest epoch when voluntary exit can be processed
    validator_index: ValidatorIndex
```

```python
class SignedVoluntaryExit(Container):
    message: VoluntaryExit
    signature: BLSSignature
```

When a validator wishes to exit from the validator list, it may create, sign, and broadcast a message of this type.
    
</details>

To accomplish this, the notion of *dynasty of a block* is introduced. The dynasty of a block $b$ is the number of finalized checkpoints in the chain from root to the parent of block $b$. When a would-be validator’s deposit message is included in a block with dynasty $d$, then the validator $v_i$ will join the validator set at first block with dynasty $d + 2$, which is called the validator’s *start dynasty*, $DS(v_i)$.
To leave the validator set, a validator must send a withdraw message. If validator $v_i$’s withdraw message is included in a block with dynasty $d$, it similarly leaves the validator set at the first block with dynasty $d + 2$, which is called the validator’s *end dynasty*, $DE(v_i)$. If a withdraw message has not yet been included, then $DE(v_i) = ∞$. Once validator $v_i$ leaves the validator set, the validator’s public key is forever forbidden from rejoining the validator set.

To generate two subsets of validators for any given dynasty $d$, the *forward validator set* and the *rear validator set* are introduced. 

$$\mathcal{V}_f(d) ≡ \{v_i : DS(v_i) \le d < DE(v_i)\}, $$

$$\mathcal{V}_r(d) ≡ \{v_i : DS(v_i) < d \le DE(v_i)\}.$$

This implies a new way to define the notion of justified and finalized checkpoints. In particular, an ordered pair of checkpoints $(s,t)$, where $t$ is in dynasty $d$, has a supermajority link if *both* at least $\frac{2}{3}$ of validators of the forward validator set of dynasty $d$ have broadcast votes $(s,t)$ *and* at least $\frac{2}{3}$ of validators of the rear validator set of dynasty $d$ have broadcast votes $(s,t)$.
Previously, a checkpoint $c$ was called finalized if $c$ is justified and there is a supermajority link $(c,c')$ with $h(c')=h(c)+1$. Now it is added the condition that $c$ is finalized if only if the votes for the supermajority link $(c,c')$, as well as the supermajority link justifying $c$, are included in $c′$’s block-tree and before the child of $c′$.


#### LMD-GHOST

The Latest Message Driven Greediest Heaviest Observed SubTree rule (**LMD-GHOST**) is a fork choice rule (A fork choice rule is a function that takes as inputs the set of blocks and other messages that have been seen, and outputs what the *canonical chain* is. This is required because there may be multiple valid chains to choose from.) introduced by [Zamfir](https://github.com/vladzamfir/research/blob/master/papers/CasperTFG/CasperTFG.pdf) while looking for a “correct-by-construction” consensus protocol. LMD-GHOST is an adaptation of the original GHOST protocol introduced by [Sompolinsky and Zohar](https://eprint.iacr.org/2013/881.pdf), a greedy algorithm that grows a blockchain on sub-branches with the “most activity”, and it guides the block production process. 

The idea behind LMD-GHOST is that at any fork, the protocol uses the weights of the subtrees created by the fork as a heuristic and assumes the subtree with the heaviest weight is the *right* one, as evident from the name of the algorithm. The weight of a subtree is determined by the sum of the stake of the validators that have cast a vote, at every slot, on each single block forming such subtree. Moreover, the protocol considers only each validator’s most recent vote (or *attestation*) (LMD).


<details><summary>Latest Message</summary>

```python
@dataclass(eq=True, frozen=True)
class LatestMessage(object):
    epoch: Epoch
    root: Root
```    

This struct represents the vote in the latest (meaning highest-epoch) valid attestation received from a validator. 
</details>


We first show informally how LMD-GHOST works through [an example](https://vitalik.ca/general/2018/12/05/cbc_casper.html), and then we present the algorithm that implements it. 

Let us consider a validator set $\mathcal{V} = \{v_1, v_2, v_3, v_4, v_5\}$ and let us assume that validator $v_1$ makes the blocks at slots 0 and 5, validator $v_2$ makes the blocks at slots 1 and 6, and so on. A client evaluating the LMD-GHOST fork choice rule cares only about the most recent (i.e., highest-slot) message (i.e., block) signed by each validator:

![](https://storage.googleapis.com/ethereum-hackmd/upload_839d656f9a58978c3dfc8cff562eae92.jpeg)


The protocol proceeds as it follows. Start from the genesis block, every time there is a fork, choose the side where more of the latest messages support that block's subtree, and keep doing this until a block with no descendants is reached. 

By computing for each block the subset of latest messages that support either the block or one of its descendants, we obtain the following.


![](https://storage.googleapis.com/ethereum-hackmd/upload_35d68aae9c279a0d9da725e63f443517.jpeg)

To compute the head, start at the beginning, and then at each fork pick the higher number: first, pick the bottom chain as it has 4 latest messages supporting it versus 1 for the single-block top chain, then at the next fork support the middle chain. 

We now present the protocol in a more formal way. First  we introduce the notions of *views* and *weight*.

Due to network delays and Byzantine validators, validators may have different set of received messages.
Each message may have one or more dependencies, where each dependency is another message. At any time, a validator *accepts a message* if and only if all of its dependencies are accepted, defined recursively. 
A *view* of a validator $v_i \in \mathcal{V}$ at a given time $t$, denoted as $\mathscr{view}(v_i, t)$, is the set of all the accepted messages that $v_i$ has seen so far. A *God’s-eye-view* is the set of accepted messages for a hypothetical validator that has seen (with no latency) all messages any validator has broadcast at any time (this includes messages sent by a Byzantine validator to only a subset of the network).

Finally, given a view $G$ (*Since usually one talks about a specific point in time, the time can be suppressed and a notation such as $\mathscr{view}(v_i)$ (or, to simplify the notation, $G$) can be used to talk about $\mathscr{view}(v_i,t)$.*), let $M$ be the set of latest attestations, one per validator. The weight $w(G,B,M)$ is defined to be the sum of the stake of the validators whose last attestation in $M$ is to $B$ or descendants of $B.$

The following algorithm implements the LMD-GHOST fork choice rule.

![](https://storage.googleapis.com/ethereum-hackmd/upload_3f3996e05c94ac56163b0994a5c11843.png)


#### FFG Casper + (H)LMD-GHOST = Gasper

As we already mentioned, **Gasper** is a proof-of-stake protocol obtained by combining the finality gadget Casper on top and (an FFG-aware variation of) the fork choice LMD-GHOST as a basis, called *Hybrid* LMD-GHOST (HLMD-GHOST). 


<details><summary>Beacon State</summary>

```python
class BeaconState(Container):
    # Versioning
    genesis_time: uint64
    genesis_validators_root: Root
    slot: Slot
    fork: Fork
    # History
    latest_block_header: BeaconBlockHeader
    block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
    state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
    historical_roots: List[Root, HISTORICAL_ROOTS_LIMIT]
    # Eth1
    eth1_data: Eth1Data
    eth1_data_votes: List[Eth1Data, EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH]
    eth1_deposit_index: uint64
    # Registry
    validators: List[Validator, VALIDATOR_REGISTRY_LIMIT]
    balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]
    # Randomness
    randao_mixes: Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]
    # Slashings
    slashings: Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]  # Per-epoch sums of slashed effective balances
    # Participation
    previous_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]
    current_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]
    # Finality
    justification_bits: Bitvector[JUSTIFICATION_BITS_LENGTH]  # Bit set for every recent justified epoch
    previous_justified_checkpoint: Checkpoint
    current_justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    # Inactivity
    inactivity_scores: List[uint64, VALIDATOR_REGISTRY_LIMIT]
    # Sync
    current_sync_committee: SyncCommittee
    next_sync_committee: SyncCommittee
    # Execution
    latest_execution_payload_header: ExecutionPayloadHeader  # [New in Bellatrix]
```

The `BeaconState` is what every validator must agree on, i.e., it is the state that every honest validator (should) reach through Gasper. It contains all the relevant information regarding the active validators, their (exact) balances, the history of the blockchain, the slashed validators, and also all the information related to justification and finalization. Everything is bundled into this single state object. 

We describe the most relevant (for this document) fields in the following.

`genesis_time`: used by the fork choice rule to figure out what slot we're in, and to validate `execution_payloads`;

`genesis_validators_root`: used to uniquely identify the chain that we are on;

`latest_block_header`: used to process blocks that are descendents of the previous block;

`block_roots` and `state_roots` are stored in lists until they are full. After that, the Merkle root is taken of both the lists together and appended to `historical_roots`;

`eth1_data`: is the latest agreed upon state of the deposit contract; 

`eth1_data_votes`: votes on `Eth1Data`;

`eth1_deposit_index`: total number of deposits that have been processed by the beacon chain;

`validators` and `balances` contain the list of all the validators and their exact balances, respecively. Recall that every validator has two balances, an effective one (stored in the `Validator` object, and that is updated less frequently), and an exact one, that changes every epoch. Here the exact one is stored.

`slashings`: used to store the total effective balance of all validators slashed in an epoch, for every epoch;

`previous_epoch_participation`: used to record which validators participated in attesting during the previous epoch;

`current_epoch_participation`: used to record which validators participated in attesting during the current epoch;

`justification_bits`: used to keep track of the justification status of the last four epochs: $1$ if justified, $0$ if not;

`previous_justified_checkpoint` and `current_justified_checkpoint` are the most recent justified `Checkpoint` as it was during the previous epoch and the most recent justified `Checkpoint` during the current epoch, respectively. They are used to filter attestations, i.e., blocks are considered valid if they include only attestations with a source checkpoint that matches the justified checkpoint the state. Moreover, they are used during the finalization process, following the rule of FFG Casper;

`finalized_checkpoint`: used to keep track of the finalized checkpoint, as a result of FFG Casper. This guarantees that the state at or before the epoch with the finalized checkpoint will never be reverted, and the fork choice rule does not need to go back more that this checkpoint;

`latest_execution_payload_header`: header of the most recent execution payload.

```python
def state_transition(state: BeaconState, signed_block: SignedBeaconBlock, validate_result: bool=True) -> None:
    block = signed_block.message
    # Process slots (including those with no blocks) since block
    process_slots(state, block.slot)
    # Verify signature
    if validate_result:
        assert verify_block_signature(state, signed_block)
    # Process block
    process_block(state, block)
    # Verify state root
    if validate_result:
        assert block.state_root == hash_tree_root(state)
```

The `state_transition` function is the function that is used to modify the `BeaconState`, processing slots (through `process_slots`), even in the case with no blocks, and blocks (through `process_block`). 

All the records/objects described in this box will be clearer after the next few sections.

</details>


In this section we show how to define justification and finalization in Gasper, and we present the Hybrid LMD-GHOST that is used among validators to choose the head/tip of the chain at any slot.

We start by presenting some preliminary notions. 

For a block $B$ and an epoch $j$, define $EBB(B, j)$, the *$j$-th epoch boundary block* of $B$, to be the block with the highest slot less than or equal to $jC$ in $\mathscr{chain}(B)$, the unique chain determined by $B$. Let the *latest* such block be $LEBB(B)$, or the last epoch boundary block (of $B$). Then, for every block $B$, $EBB(B, 0)$ is the genesis block. More generally, if $\mathscr{slot}(B) = jC$ for some epoch $j$, $B$ will be an epoch boundary block in every chain that includes it.

However, a block could be an epoch boundary block in some chains but not others. For this reason, *epoch boundary pairs* (or pairs for short) *(B, j)* are introduced, where $B$ is a block and $j$ is an epoch. These epoch boundary pairs are considered to play the role of Casper's checkpoints. A pair $P = (B, j)$ has *attestation epoch* $j$, denoted as $\mathscr{aep}(P) = j$. Observe that this is not necessarily the same as $\mathscr{ep}(B)$, i.e., the epoch of $B$. In fact, $\mathscr{ep}()$ is a local property that only depends on the block’s slot, while epoch boundary concepts like $\mathscr{aep}()$ depend on the context of the chain. Note that, without loss of generality, sometimes slot numbers are used as argument for $\mathscr{ep}$ and $\mathscr{aep}$ instead of blocks. It is clear that at any block $B$ corresponds a slot number. Moreover, $\mathscr{ep}(\alpha)$ is sometimes used as shorthand for $\mathscr{ep}(\mathscr{slot}(\alpha))$.

![](https://storage.googleapis.com/ethereum-hackmd/upload_b9d78fc7c37d93db2c139d73279a33e9.png)

In the image above, $\mathscr{aep}(63, 1)$ and $\mathscr{ep}(63) = 0$.

Finally, observe that, in Gasper, instead of justifying and finalizing checkpoint blocks as with Casper, epoch boundary pairs are justified and finalized.

Given a block $B$, we define $\mathscr{view}(B)$, the view of $B$, to be the view consisting of $B$ and all its ancestors. We define $\mathscr{ffgview}(B)$, the FFG view of $B$, to be $\mathscr{view}(LEBB(B))$.
The definition of $\mathscr{view}(B)$ is *agnostic of the viewer*, in the sense that any view that accepted $B$ can compute an identical $\mathscr{view}(B)$, so we do not need to supply a validator into the argument. Intuitively, $\mathscr{view}(B)$ *focuses* the view to the chain starting from the genesis block to $B$ and $\mathscr{ffgview}(B)$ looks at a *frozen* snapshot of $\mathscr{view}(B)$ at the last checkpoint. Casper FFG operates only on epoch boundary pairs, so the FFG view of a block $B$ extracts exactly the information in the chain starting from the genesis block to $B$ that is relevant to Casper FFG.

In Gasper, validators are partitioned into *committees* in each epoch, with one committee per slot. In each slot, one validator from the designated committee proposes a block. Then, all the members of that committee will *attest* to what they see as the head of the chain with the fork choice rule HLMD-GHOST (a slight variation of LMD-GHOST that will be presented below).

More in details, in each slot, the protocol requires validators to carry out two types of work. One validator in the committee, called *proposer*, needs to *propose* a new block (which is a message containing the slot number, a pointer to the parent block, a set of pointers to all the attestations that the validator has accepted, but have not been included in any other ancestor block, and some implementation-specific data).



<details><summary>Beacon Block</summary>

```python
class BeaconBlockBody(Container):
    randao_reveal: BLSSignature
    eth1_data: Eth1Data  # Eth1 data vote
    graffiti: Bytes32  # Arbitrary data
    # Operations
    proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]
    attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]
    attestations: List[Attestation, MAX_ATTESTATIONS]
    deposits: List[Deposit, MAX_DEPOSITS]
    voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]
    sync_aggregate: SyncAggregate
    # Execution
    execution_payload: ExecutionPayload  # [New in Bellatrix]
```

The `BeaconBlock` is the block that the proposer for a given slot creates and communicates to the network. This block, if correct, will update the `BeaconState` of every honest validator. Validators are randomly selected to propose `BeaconBlock`s, and there can be at most one `BeaconBlock` per slot.

`randao_reveal`: record used for randomness purposes. The proposer generates it by signing the current epoch number with its private key;

`eth1_data`: record used in a pre-merge version of Ethereum consensus protocol, and it is/was used for the deposits of validators;

`graffiti`: record used by the proposer to insert whatever data it wishes. It has no protocol level significance; 

`proposer_slashings`: contains up to `MAX_PROPOSER_SLASHINGS` `ProposerSlashing` objects (see below);

`attester_slashings`: contains up to `MAX_ATTESTER_SLASHINGS` `AttesterSlashing` objects (see below);

`attestations`: contains up to `MAX_ATTESTATIONS` `Attestation objects` (see below). The proposer earns a reward for including well-packed aggregate attestations;

`deposits`: if the block does not contain all the outstanding `Deposits`, it is considered invalid;

`voluntary_exits`: contains up to `MAX_VOLUNTARY_EXITS` `SignedVoluntaryExit` objects;

`sync_aggregate`: is a record voted from the current sync committee for the chain head in the previous slot;

`execution_payload`: Ethereum transactions are included in this record.


```python
class BeaconBlock(Container):
    slot: Slot
    proposer_index: ValidatorIndex
    parent_root: Root
    state_root: Root
    body: BeaconBlockBody
```

</details>

Moreover, everyone in the committee needs to attest to their head of the chain with an attestation $\alpha$ (which is a message containing the slot in which the validator is making the attestation, $\mathscr{slot}(\alpha)$, the target block a validator is attesting to, $\mathscr{block}(\alpha)$, and a checkpoint edge between two epoch boundary pairs, $LJ(\alpha) \rightarrow LE(\alpha)$). Both of them require to add a corresponding block and an attestation, respectively, to the validator's view, and then to broadcast it to the network. Observe that both proposing and attesting requires the committee member to run the same fork choice rule on the validator's own view.

Note that, while attesting, a validator does two things at once: it is simultaneously casting a GHOST vote for its block and also a Casper FFG vote for the transition between the two epoch boundary pairs (akin to Casper’s checkpoint blocks).

<details><summary>Attestation</summary>


```python
class AttestationData(Container):
    slot: Slot
    index: CommitteeIndex
    # LMD GHOST vote
    beacon_block_root: Root
    # FFG vote
    source: Checkpoint
    target: Checkpoint
```

`AttestationData` contains information about the attestation that a validator sent to the network in a given slot.

`slot`: slot in which a validator is casting the attestation. It is recorded here for validation purposes;

`index`: there can be several committees active in a single slot. This is the number of the committee that the validator belongs to in that slot; 

`beacon_block_root` is the validator's vote on the head block for that slot after locally running the LMD GHOST fork choice rule. If the validator believes that the current slot is empty, then this record might be the root of a block from a previous slot;

`source`: the best currently justified checkpoint for the Casper FFG finalisation process, according to the validator;

`target`: the block at the start of the current epoch (EBB), also for Casper FFG finalization, according to the validator;

`AttestationData` is wrapped in the following.

```python
class Attestation(Container):
    aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE]
    data: AttestationData
    signature: BLSSignature
```

```python

def process_attestation(state: BeaconState, attestation: Attestation) -> None:
    data = attestation.data
    assert data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))
    assert data.target.epoch == compute_epoch_at_slot(data.slot)
    assert data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot <= data.slot + SLOTS_PER_EPOCH
    assert data.index < get_committee_count_per_slot(state, data.target.epoch)

    committee = get_beacon_committee(state, data.slot, data.index)
    assert len(attestation.aggregation_bits) == len(committee)

    # Participation flag indices
    participation_flag_indices = get_attestation_participation_flag_indices(state, data, state.slot - data.slot)

    # Verify signature
    assert is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))

    # Update epoch participation flags
    if data.target.epoch == get_current_epoch(state):
        epoch_participation = state.current_epoch_participation
    else:
        epoch_participation = state.previous_epoch_participation

    proposer_reward_numerator = 0
    for index in get_attesting_indices(state, data, attestation.aggregation_bits):
        for flag_index, weight in enumerate(PARTICIPATION_FLAG_WEIGHTS):
            if flag_index in participation_flag_indices and not has_flag(epoch_participation[index], flag_index):
                epoch_participation[index] = add_flag(epoch_participation[index], flag_index)
                proposer_reward_numerator += get_base_reward(state, index) * weight

    # Reward proposer
    proposer_reward_denominator = (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR // PROPOSER_WEIGHT
    proposer_reward = Gwei(proposer_reward_numerator // proposer_reward_denominator)
    increase_balance(state, get_beacon_proposer_index(state), proposer_reward)

```

This function processes attestations included in `BeaconBlockBody`. First it performs some validity checks such as, for example, that the target checkpoint and the attestation's slot must belong to the same epoch, or that the attestation must be no older than `SLOTS_PER_EPOCH` ($32$) slots. Then, once the attestation has passed all the validity checks, it is processed.

</details>

In the previous section, the notion of justification and finalization were given in the context of FFG Casper. For Gasper, these are extended as it follows.

Recall an attestation $\alpha$ for Gasper contains a checkpoint edge $LJ(\alpha) \rightarrow LE(\alpha)$ between epoch boundary pairs, acting as a FFG vote between two epoch boundary pairs. If at least $\frac{2}{3}$ of validators have broadcast votes with source $(A,j')$ and target $(B,j)$, then there is a *supermajority link* from epoch boundary pairs $(A,j')$ and $(B,j),$ denoted with $(A,j') \xrightarrow[]{J} (B,j)$.

Given a view $G$, the set $J(G)$ of *justified* pairs is such that $(B_{\text{genesis}}, 0) \in J(G)$ and if $(A,j') \in J(G)$ and $(A,j') \xrightarrow[]{J} (B,j)$ , then $(B,j) \in J(G)$, i.e., $B$ is justified in $G$ during epoch $j.$ 

With the notion of justification, it becomes clearer then what both $LJ(\alpha)$ and $LE(\alpha)$ mean: $LJ(\alpha)$ is the last justified pair of $\alpha$, i.e., the last justified pair in $\mathscr{ffgview}(\mathscr{block}(\alpha))=\mathscr{view}(B)$, while $LE(\alpha)$ is the last epoch boundary pair of $\alpha$, i.e., $(B, \mathscr{ep}(\mathscr{slot}(\alpha)))$


![](https://storage.googleapis.com/ethereum-hackmd/upload_0fd519d0f87f4080f1fe75b73e45830b.png)

A validator’s view $G$ as she writes an attestation in epoch $3$. During epoch $1$, latency issues make her not see any blocks, so block $64$ is both $EBB(193, 1)$ and $EBB(193, 2)$. She ends up writing an attestation $\alpha$ with a GHOST vote for $\mathscr{block}(\alpha) = 193$ and a FFG vote checkpoint edge (single arc edge) $(64,2) \rightarrow (180,3)$ for $\alpha$. Blocks in red are justified (in $G$). Double edges corresponding to supermajority links. Then, $LE(\alpha) = (180, 3)$, even though $\mathscr{ep}(180) = 2$. In $\mathscr{ffgview}(193) = \mathscr{view}(180)$, the last justified (by epoch number, not slot) pair is (64, 2), so $LJ(\alpha) = (64, 2)$.

Everything here is analogous to Casper FFG. Inside the chain of $\mathscr{block}(\alpha)$ is a sub-chain created by the epoch boundary blocks of that chain, starting from Bgenesis and ending at $B = LEBB(\alpha)$.

For a view $G$, a pair $(B_0, j)$ is *finalized* (specifically, $k$-finalized) in $G$ if $(B_0, j) = (B_{\text{genesis}},0)$ or if there is  an integer $k \ge 1$ and blocks $B_1,...,B_k \in G$ such that the following holds:
* $(B_0,j),(B_1,j+1),...,(B_k,j+k)$ are adjacent epoch  boundary pairs in $\mathscr{chain}(B_k)$; 
* $(B_0,j),(B_1,j+1),...,(B_{k−1},j+k−1)$ are all in $J(G)$;
* $(B_0,j) \xrightarrow[]{J} (B_k,j+k)$.

The set $F(G)$ is the set of finalized pairs in the view $G$; a block $B$ is finalized if $(B,j) \in F(G)$ for some epoch $j$. For the vast majority of time, $1$-finalized (or $2$-finalized) blocks are expected.


<details><summary>Justification and Finalization</summary>


```python
def process_justification_and_finalization(state: BeaconState) -> None:
    # Initial FFG checkpoint values have a `0x00` stub for `root`.
    # Skip FFG updates in the first two epochs to avoid corner cases that might result in modifying this stub.
    if get_current_epoch(state) <= GENESIS_EPOCH + 1:
        return
    previous_indices = get_unslashed_participating_indices(state, TIMELY_TARGET_FLAG_INDEX, get_previous_epoch(state))
    current_indices = get_unslashed_participating_indices(state, TIMELY_TARGET_FLAG_INDEX, get_current_epoch(state))
    total_active_balance = get_total_active_balance(state)
    previous_target_balance = get_total_balance(state, previous_indices)
    current_target_balance = get_total_balance(state, current_indices)
    weigh_justification_and_finalization(state, total_active_balance, previous_target_balance, current_target_balance)
```
FFG Casper happens in `process_justification_and_finalization`. 

`get_unslashed_participating_indices()`: returns the validators that made a timely attestation with the type `TIMELY_TARGET_FLAG_INDEX` during the epoch in question. It is used to calculate the proportion of stake that voted for the candidate checkpoint in the current and previous epochs. Observe that if a validator $v_i$ has the flag `TIMELY_TARGET_FLAG_INDEX` set, it means that a correct source and target have been used in the attestation broadcasted by $v_i$. In other words, if validator $v_i$ broadcasts an attestation $\alpha$ with correct source $s$ and target $t$ in epoch $n$, then for epoch $n$ validator $v_i$ has the flag `TIMELY_TARGET_FLAG_INDEX`. Moreover, if $v_i$ has not been slashed, then the index $i$ will be returned by `get_unslashed_participating_indices(state, TIMELY_TARGET_FLAG_INDEX, n)`;

`get_total_active_balance(state: BeaconState)`: the sum of the *effective balances* of all active validators in the current epoch (slashed validators are not included);

`get_total_balance(state: BeaconState, indices: Set[ValidatorIndex])`: returns the total balance of all validators in the list `indices` passed in.

The function `process_justification_and_finalization` takes the lists of unslashed validators in the current and previous epochs, gets their respective total balances, and calculates the sum of the *effective balances* of all active validators in the current epoch. Then, these aggregate balances are passed to the following function for justification and finalization.


```python
def weigh_justification_and_finalization(state: BeaconState,
                                         total_active_balance: Gwei,
                                         previous_epoch_target_balance: Gwei,
                                         current_epoch_target_balance: Gwei) -> None:
    previous_epoch = get_previous_epoch(state)
    current_epoch = get_current_epoch(state)
    old_previous_justified_checkpoint = state.previous_justified_checkpoint
    old_current_justified_checkpoint = state.current_justified_checkpoint

    # Process justifications
    state.previous_justified_checkpoint = state.current_justified_checkpoint
    state.justification_bits[1:] = state.justification_bits[:JUSTIFICATION_BITS_LENGTH - 1]
    state.justification_bits[0] = 0b0
    if previous_epoch_target_balance * 3 >= total_active_balance * 2:
        state.current_justified_checkpoint = Checkpoint(epoch=previous_epoch,
                                                        root=get_block_root(state, previous_epoch))
        state.justification_bits[1] = 0b1
    if current_epoch_target_balance * 3 >= total_active_balance * 2:
        state.current_justified_checkpoint = Checkpoint(epoch=current_epoch,
                                                        root=get_block_root(state, current_epoch))
        state.justification_bits[0] = 0b1

    # Process finalizations
    bits = state.justification_bits
    # The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if all(bits[1:4]) and old_previous_justified_checkpoint.epoch + 3 == current_epoch:
        state.finalized_checkpoint = old_previous_justified_checkpoint
    # The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if all(bits[1:3]) and old_previous_justified_checkpoint.epoch + 2 == current_epoch:
        state.finalized_checkpoint = old_previous_justified_checkpoint
    # The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if all(bits[0:3]) and old_current_justified_checkpoint.epoch + 2 == current_epoch:
        state.finalized_checkpoint = old_current_justified_checkpoint
    # The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if all(bits[0:2]) and old_current_justified_checkpoint.epoch + 1 == current_epoch:
        state.finalized_checkpoint = old_current_justified_checkpoint
```

Given a `BeaconState`, the function `weigh_justification_and_finalization` first handles the justification, and then the finalization. 

Recall that the `justification_bits` record contained in the `BeaconState` is used to keep track of the justification status of the last four epochs: $1$ if justified, $0$ if not. For example, if we are in epoch $7$, then `state.justification_bits[0]` represents the justification state of epoch $7$ and `state.justification_bits[3]=1` means that epoch $4$ is justified, i.e., that at least $\frac{2}{3}$ of the validators cast a vote $⟨v_i, a, b, h(a), h(b)⟩$ with (a justified) checkpoint $a$ and an epoch boundary block $b$ for epoch $4$.

In particular, in the first part (# Process justifications), given the balances of the previous and the current epochs (i.e., the total amount of deposits of the active validators that cast a vote in the previous and current epochs), the two `if` statements try to justify the previous and the current epoch's checkpoints, respectively. If both the `if` statements return true, then before the finalization process starts we have `state.justification_bits[0]=state.justification_bits[1]=1`.

For the second part, (# Process finalizations), observe that a $2$-finalization rule is used. In particular, for a view $G$, a pair $(B_0, j)$ is $2$-finalized in $G$ if $(B_0, j) = (B_{\text{genesis}},0)$ or if there are two blocks $B_1, B_2 \in G$ such that the following holds:
* $(B_0,j),(B_1,j+1),(B_2,j+2)$ are adjacent epoch boundary pairs in $\mathscr{chain}(B_2)$; 
* $(B_0,j),(B_1,j+1)$ are all in $J(G)$;
* $(B_0,j) \xrightarrow[]{J} (B_2,j+2)$.

In `weigh_justification_and_finalization`,

* the first condition reflects on requiring that `old_previous_justified_checkpoint.epoch + 3 == current_epoch` and `old_previous_justified_checkpoint.epoch + 2 == current_epoch`;
* the second condition reflects on requiring that `state.justification_bits[3]=state.justification_bits[2]=1`; and
* the third condition reflects on requiring that `state.justification_bits[1]=1`. In particular, if `state.justification_bits[0]=state.justification_bits[1]=1` (from the justification process above) and if `state.justification_bits[3]=state.justification_bits[2]=1`, then the existence of supermajority links is implied. 

</details>

We can now finally present HLMD-GHOST, a variation of LMD-GHOST. In this variation, the protocol freezes the state of the latest justified pair $(B_J , j)$ to the beginning of the epochs; formally, this means when defining $(B_J , j)$ the protocol considers the views of $\mathscr{ffgview}(B_l)$ over the leaf blocks $B_l$. Then, it filters the branches so one does not go down branches with leaf nodes $B_l$ where $LJ(B_l)$ has not *caught up* to $(B_J,j)$; formally, an auxiliary view $G'$ from $G$ is created. This filtering prevents scenarios in which, when the algorithm forks, forked blocks have different last justified pairs. In fact, if this happened and no filtering was applied, if a validator $v_i$ that previously attested to a higher last justification epoch forks into a chain whose last justification epoch is older, then $v_i$ may end up slashing itself (see just below).


![](https://storage.googleapis.com/ethereum-hackmd/upload_57c971f6b4e0557970910dc3eef486a7.png)


One can think of each chain of a leaf block $B_l$ as storing the state of its own last justified pair. During an epoch, new attestations to blocks in the chain updates the GHOST-relevant list of latest attestations $M$ but not the FFG-relevant justification and finalization information of the chain until the next epoch boundary block. This way, the *FFG part* of the protocol always works with the *frozen until next epoch* information, while the *GHOST part* of the protocol is being updated continuously with the attestations.

<details><summary>Fork Choice</summary>

The fork choice is implemented through a `store` object that contains received fork-choice-relevant information, and a function `get_head(store)`.

```python
@dataclass
class Store(object):
    time: uint64
    genesis_time: uint64
    justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    best_justified_checkpoint: Checkpoint
    proposer_boost_root: Root
    equivocating_indices: Set[ValidatorIndex]
    blocks: Dict[Root, BeaconBlock] = field(default_factory=dict)
    block_states: Dict[Root, BeaconState] = field(default_factory=dict)
    checkpoint_states: Dict[Checkpoint, BeaconState] = field(default_factory=dict)
    latest_messages: Dict[ValidatorIndex, LatestMessage] = field(default_factory=dict)
```

The records here are as it follows.

`time`: the current time;

`genesis_time`: the time of the genesis block of the chain;

`justified_checkpoint`: the FFG-Casper-justified checkpoint that is used as the root of the HLMD-GHOST fork choice;

`finalized_checkpoint`: the last finalized checkpoint; 

`best_justified_checkpoint`: the justified checkpoint that we will switch to at the start of the next epoch;

`proposer_boost_root`:  a special `LatestMessage` that stores the boost [https://github.com/ethereum/consensus-specs/pull/2730] (see the section on *Proposer Weight Boosting*);

`equivocating_indices`: list of validators that equivocated, i.e., cast contradictory votes [https://github.com/ethereum/consensus-specs/pull/2845] (see the section on *Equivocation Discounting*);

`blocks`: all blocks that we know about;

`block_states`: the post-state of every block that we know about;

`checkpoint_states`: the post-state of every checkpoint. This could be different from the post-state of the block referenced by the checkpoint in the case where there are skipped slots; 

`latest_messages`: the latest epoch and block voted for by each validator;


At genesis, let `store = get_forkchoice_store(genesis_state)` and update store by running:

(i)

```python
def on_tick(store: Store, time: uint64) -> None:
    previous_slot = get_current_slot(store)

    # update store time
    store.time = time

    current_slot = get_current_slot(store)

    # Reset store.proposer_boost_root if this is a new slot
    if current_slot > previous_slot:
        store.proposer_boost_root = Root()

    # Not a new epoch, return
    if not (current_slot > previous_slot and compute_slots_since_epoch_start(current_slot) == 0):
        return

    # Update store.justified_checkpoint if a better checkpoint on the store.finalized_checkpoint chain
    if store.best_justified_checkpoint.epoch > store.justified_checkpoint.epoch:
        finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)    
        ancestor_at_finalized_slot = get_ancestor(store, store.best_justified_checkpoint.root, finalized_slot)
        if ancestor_at_finalized_slot == store.finalized_checkpoint.root:
            store.justified_checkpoint = store.best_justified_checkpoint
```

This function runs on each tick. At the end of each epoch, update the justified checkpoint used in the fork choice;

(ii)

```python
def on_attestation(store: Store, attestation: Attestation) -> None:
    """
    Run ``on_attestation`` upon receiving a new ``attestation`` from either within a block or directly on the wire.

    An ``attestation`` that is asserted as invalid may be valid at a later time,
    consider scheduling it for later processing in such case.
    """
    validate_on_attestation(store, attestation)
    store_target_checkpoint_state(store, attestation.data.target)

    # Get state at the `target` to fully validate attestation
    target_state = store.checkpoint_states[attestation.data.target]
    indexed_attestation = get_indexed_attestation(target_state, attestation)
    assert is_valid_indexed_attestation(target_state, indexed_attestation)

    # Update latest messages for attesting indices
    update_latest_messages(store, indexed_attestation.attesting_indices, attestation)
```
This function runs whenever an attestation attestation is received; and

(iii)

```python
def on_block(store: Store, signed_block: SignedBeaconBlock) -> None:
    """
    Run ``on_block`` upon receiving a new block.

    A block that is asserted as invalid due to unavailable PoW block may be valid at a later time,
    consider scheduling it for later processing in such case.
    """
    block = signed_block.message
    # Parent block must be known
    assert block.parent_root in store.block_states
    # Make a copy of the state to avoid mutability issues
    pre_state = copy(store.block_states[block.parent_root])
    # Blocks cannot be in the future. If they are, their consideration must be delayed until they are in the past.
    assert get_current_slot(store) >= block.slot

    # Check that block is later than the finalized epoch slot (optimization to reduce calls to get_ancestor)
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    assert block.slot > finalized_slot
    # Check block is a descendant of the finalized block at the checkpoint finalized slot
    assert get_ancestor(store, block.parent_root, finalized_slot) == store.finalized_checkpoint.root

    # Check the block is valid and compute the post-state
    state = pre_state.copy()
    state_transition(state, signed_block, True)

    # [New in Bellatrix]
    if is_merge_transition_block(pre_state, block.body):
        validate_merge_block(block)

    # Add new block to the store
    store.blocks[hash_tree_root(block)] = block
    # Add new state for this block to the store
    store.block_states[hash_tree_root(block)] = state

    # Add proposer score boost if the block is timely
    time_into_slot = (store.time - store.genesis_time) % SECONDS_PER_SLOT
    is_before_attesting_interval = time_into_slot < SECONDS_PER_SLOT // INTERVALS_PER_SLOT
    if get_current_slot(store) == block.slot and is_before_attesting_interval:
        store.proposer_boost_root = hash_tree_root(block)

    # Update justified checkpoint
    if state.current_justified_checkpoint.epoch > store.justified_checkpoint.epoch:
        if state.current_justified_checkpoint.epoch > store.best_justified_checkpoint.epoch:
            store.best_justified_checkpoint = state.current_justified_checkpoint
        if should_update_justified_checkpoint(store, state.current_justified_checkpoint):
            store.justified_checkpoint = state.current_justified_checkpoint

    # Update finalized checkpoint
    if state.finalized_checkpoint.epoch > store.finalized_checkpoint.epoch:
        store.finalized_checkpoint = state.finalized_checkpoint
        store.justified_checkpoint = state.current_justified_checkpoint
```

This function runs whenever a `SignedBeaconBlock` is received.

Any of the above handlers that trigger an unhandled exception are considered invalid. Invalid calls to handlers must not modify `store`.

Observe that `best_justified_checkpoint` is stored to prevend an attack on FFG Casper [https://ethresear.ch/t/analysis-of-bouncing-attack-on-ffg/6113]. In particular, `on_block` uses the following function.

```python
def should_update_justified_checkpoint(store: Store, new_justified_checkpoint: Checkpoint) -> bool:
    """
    To address the bouncing attack, only update conflicting justified
    checkpoints in the fork choice if in the early slots of the epoch.
    Otherwise, delay incorporation of new justified checkpoint until next epoch boundary.

    See https://ethresear.ch/t/prevention-of-bouncing-attack-on-ffg/6114 for more detailed analysis and discussion.
    """
    if compute_slots_since_epoch_start(get_current_slot(store)) < SAFE_SLOTS_TO_UPDATE_JUSTIFIED:
        return True

    justified_slot = compute_start_slot_at_epoch(store.justified_checkpoint.epoch)
    if not get_ancestor(store, new_justified_checkpoint.root, justified_slot) == store.justified_checkpoint.root:
        return False

    return True

```

*The idea here is that we want to only change the last-justified-block within the first $\frac{1}{3}$ of an epoch. This prevents bouncing attacks of the following form.* Observe that the following blocks, i.e., $A,B,A',...$, are EBB in Gasper.

* *Start from a scenario where in epoch $n$, $62\%$ of validators support block $A$, and in epoch $n+1$, $62\%$ of validators support a block $B$. Suppose that the attacker has $5\%$ of the total stake. This scenario requires very exceptional networking conditions to get into; the point of the attack, however, is that if we get into such a scenario the attacker could perpetuate it, permanently preventing finality.*
* *Due to LMD-GHOST, $B$ is favored, and so validators are continuing to vote for $B$. However, the attacker suddenly publishes attestations worth $5\%$ of the total stake tagged with epoch $n$ for block $A$, causing $A$ to get justified.*
* *In epoch $n+2$, $A$ is justified and so validators are attesting to $A'$, a descendant of $A$. When $A'$ gets to $62\%$ support, the attacker publishes attestations worth $5\%$ of total stake tagged with epoch $n+1$ for $B$. Now $B$ is justified and favored by the fork choice.*
* *In epoch $n+3$, $B$ is justified, and so validators are attesting to $B'$, a descendant of $B$. When $B'$ gets to $62\%$ support, the attacker publishes attestations worth $5\%$ of total stake tagged with epoch $n+2$ for $A'$, etc.*

*This could continue forever, bouncing permanently between the two chains preventing any new block from being finalized. This attack can happen because the combined use of LMD-GHOST and FFG Casper creates a discontinuity, where a small shift in support for a block can outweigh a large amount of support for another block if that small shift pushes it past the $\frac{2}{3}$ threshold needed for justification. We block the attack by only allowing the latest justified block to change near the beginning of an epoch; this way, there is a full $\frac{2}{3}$ of an epoch during which honest validators agree on the head and have the opportunity to justify a block and thereby further cement it, at the same time causing the LMD-GHOST rule to strongly favor that head. This sets up that block to most likely be finalized in the next epoch.* [https://github.com/ethereum/annotated-spec/blob/master/phase0/fork-choice.md#should_update_justified_checkpoint]

The following function initializes the `store` given a particular block (the `anchor_block`) that the fork choice would start from. The provided `anchor-state` will be regarded as a trusted state. 

```python
def get_forkchoice_store(anchor_state: BeaconState, anchor_block: BeaconBlock) -> Store:
    assert anchor_block.state_root == hash_tree_root(anchor_state)
    anchor_root = hash_tree_root(anchor_block)
    anchor_epoch = get_current_epoch(anchor_state)
    justified_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
    finalized_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
    proposer_boost_root = Root()
    return Store(
        time=uint64(anchor_state.genesis_time + SECONDS_PER_SLOT * anchor_state.slot),
        genesis_time=anchor_state.genesis_time,
        justified_checkpoint=justified_checkpoint,
        finalized_checkpoint=finalized_checkpoint,
        best_justified_checkpoint=justified_checkpoint,
        proposer_boost_root=proposer_boost_root,
        equivocating_indices=set(),
        blocks={anchor_root: copy(anchor_block)},
        block_states={anchor_root: copy(anchor_state)},
        checkpoint_states={justified_checkpoint: copy(anchor_state)},
    )
```

Finally, the main fork choice function is given by the following.


```python
def get_head(store: Store) -> Root:
    # Get filtered block-tree that only includes viable branches
    blocks = get_filtered_block_tree(store)
    # Execute the LMD-GHOST fork choice
    head = store.justified_checkpoint.root
    while True:
        children = [
            root for root in blocks.keys()
            if blocks[root].parent_root == head
        ]
        if len(children) == 0:
            return head
        # Sort by latest attesting balance with ties broken lexicographically
        # Ties broken by favoring block with lexicographically higher root
        head = max(children, key=lambda root: (get_latest_attesting_balance(store, root), root))
``` 

The function `get_head` returns the head of the chain. *This follows the following procedure:*

* *Get the latest justified block hash, call it $B$ (this is implicit in `get_filtered_block_tree`)*;
* *Get the subtree of blocks rooted in $B$ (done by `get_filtered_block_tree`)*;
* *Filter that for blocks whose slot exceeds the slot of $B$*;
* *Walk down the tree, at each step where a block has multiple children selecting the child with the strongest support i.e., higher `get_latest_attesting_balance`* [https://github.com/ethereum/annotated-spec/blob/master/phase0/fork-choice.md#get_head]

</details>

Finally, as showed with FFG Casper, in Gasper validators must not make two distinct attestations $\alpha_1$ and $\alpha_2$ with $\mathscr{ep}(\mathscr{slot}(\alpha_1)))=\mathscr{ep}(\mathscr{slot}(\alpha_2)))$ and must not make two disting attestations $\alpha_1$ and $\alpha_2$ with $$\mathscr{aep}(LJ(\alpha_1)) < \mathscr{aep}(LJ(\alpha_2)) < \mathscr{aep}(LE(\alpha_2)) < \mathscr{aep}(LE(\alpha_1)).$$


<details><summary>Slashing</summary>

```python
def is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool:
    """
    Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
    """
    return (
        # Double vote
        (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
        # Surround vote
        (data_1.source.epoch < data_2.source.epoch and data_2.target.epoch < data_1.target.epoch)
    )
```

</details>

If a validator violates either condition, the evidence of the violation can be observed, at which point the validator’s deposit is slashed with a reward given to the submitter of the evidence transaction. 


<details><summary>More on Slashing</summary>

```python
class ProposerSlashing(Container):
    signed_header_1: SignedBeaconBlockHeader
    signed_header_2: SignedBeaconBlockHeader
```

```python
class AttesterSlashing(Container):
    attestation_1: IndexedAttestation
    attestation_2: IndexedAttestation
```

</details>


### Properties of Gasper

In this section we present the properties that Gasper *should* satisfy as a consensus protocol, following the formalization introduced by [Neu *et al.*](https://arxiv.org/pdf/2009.04987.pdf)

However, due to some discovered attacks (that will be presented in the following sections), these properties are not guaranteed in the original version of Gasper, i.e., the version presented above.

The goal of a consensus protocol is to allow all participants to reach a common decision despite the presence of faulty ones. In our context, this translates into allowing honest validators to grow a chain that is finalized and where all blocks constitute consistent state transitions with each other. Here we assume validators being Byzantine, being potentially offline, or suffering latency problems. In other terms, this translates to the following properties.

* **Safety**: If the set of finalized blocks $F(G)$ for any view $G$ can never contain two conflicting blocks. 
* **Liveness**: If the set of finalized blocks can actually grow. 

#### Availability-Finality Dilemma

A novelty that blockchains have introduced is the notion of *dynamically available* protocols, i.e., consensus protocols that can support an unknown and variable number of participants. 
One limitation of these protocols is that they are not tolerant to network partitions. In particular, when the network partitions, honest participants in a dynamically available protocol will think that many participants are asleep and keep confirming transactions, potentially leading to safety violations. A different approach is instead taken by standard permissioned BFT protocols such as PBFT or HotStuff. These are designed for partially synchronous networks, and a quorum of at least two-thirds of all the participants is required to finalize transactions, ensuring safety under network partition, but not liveness. Liveness is guaranteed only after GST. It is *impossible* for any consensus protocol to be both safe under network partition and live under dynamic participation.

In other words, *the availability-finality dilemma says that there cannot be a consensus protocol for state-machine replication, one that outputs a single ledger, that provides both properties. The next best thing is then to ask for a protocol with two confirmation rules that outputs two ledgers, one that provides availability under dynamic participation, and one that provides finality even under network partitions, and in the long run they should agree on a common account of history.* [https://decentralizedthoughts.github.io/2020-11-01-ebb-and-flow-protocols-a-resolution-of-the-availability-finality-dilemma/]

Based on this observation, [Neu *et al.*](*https://arxiv.org/pdf/2009.04987.pdf) gave a formalization of the properties that Gasper, according to its design goals, should satisfy. In particular, given the time model described at the beginning of this document, they define the notion of $(\beta_1,\beta_2)$*-secure ebb-and-flow protocol* to be a protocol that outputs an available ledger $𝖫𝖮𝖦_{\text{da}}$ and a finalized ledger $𝖫𝖮𝖦_{\text{fin}}$ satisfying the following properties:

* **Finality**: The finalized ledger $𝖫𝖮𝖦_{\text{fin}}$ is guaranteed to be accountable safe (in the event of a safety violation, one can provably identify Byzantine validators that have violated the protocol) at all times, and live after $\max\{𝖦𝖲𝖳,𝖦𝖠𝖳\}$, provided that fewer than $\beta_1$ proportion of all the nodes are adversarial.
* **Dynamic Availability**: If $𝖦𝖲𝖳=0$, i.e., if the network is synchronous, the available ledger $𝖫𝖮𝖦_{\text{da}}$ is guaranteed to be safe and live at all times, provided that at all times fewer than $\beta_2$ proportion of the awake nodes are adversarial.
* **Prefix**: $𝖫𝖮𝖦_{\text{fin}}$ is a prefix of $𝖫𝖮𝖦_{\text{da}}$ at all times.

In the case of Gasper, we want $\beta_1 = 33 \%$ and $\beta_2=50 \%.$

In other words, *together, Finality and Dynamic Availability say that the finalized ledger $𝖫𝖮𝖦_{\text{fin}}$ is safe under network partitions, i.e., before $\max\{𝖦𝖲𝖳,𝖦𝖠𝖳\}$, and can experience liveness violations before GST or GAT, and afterwards (after validators wake up and the network turns synchronous) catches up with the available ledger $𝖫𝖮𝖦_{\text{da}}$. The Prefix property ensures that eventually all clients, no matter what confirmation rule they follow, will still agree on a single account of history.* [https://decentralizedthoughts.github.io/2020-11-01-ebb-and-flow-protocols-a-resolution-of-the-availability-finality-dilemma/]

### Weak Subjectivity

One of the problems that proof-of-stake consensus protocols have is that they are subject to long-range attacks. In a long-range attack, an adversary corrupts past participants in the consensus protocol in order to re-write the history of the blockchain. The reason why this attack can be placed in a proof-of-stake-based system is because, in such system, the creation of a block is costless, contrary to proof-of-work-based systems where some external resource, e.g., computation, must be spent in order to create a new block.

In practice, many proof-of-stake systems deal with long-range attacks by requiring key-evolving cryptography, using more refined chain selection rules, or other techniques. In the case of Ethereum, Gasper deals with long-range attacks through *weak subjectivity checkpoints*.

To understand what a weak subjectivity checkpoint is, we first properly recall the notion of weak subjectivity, as introduced by Buterin in 2014.

A consensus protocol can be categorized according to the following paradigms.

* **Objective**: *a new node coming onto the network with no knowledge except (i) the protocol definition and (ii) the set of all blocks and other important messages that have been published can independently come to the exact same conclusion as the rest of the network on the current state.* (This is the case of proof-of-work-based blockchains, such as Bitcoin)
* **Subjective**: *the system has stable states where different nodes come to different conclusions, and a large amount of social information  is required in order to participate.* (This is the case of social-network-based blockchains, such as Stellar)

For proof-of-stake, a third paradigm can be defined.

* **Weakly subjective**: *a new node coming onto the network with no knowledge except (i) the protocol definition, (ii) the set of all blocks and other important messages that have been published and (iii) a state from less than $N$ blocks ago that is known to be valid can independently come to the exact same conclusion as the rest of the network on the current state, unless there is an attacker that permanently has more than $X$ percent control over the consensus set.* [https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity]


In other terms, through weak subjectivity it is possible to obtain checkpoints that acts as new genesis block, and we forbid participants from reverting more than $N$ blocks. Long-range attacks are then no longer a problem, because long-range forks are declared to be invalid as part of the protocol definition.
These checkpoints are called weak subjectivity checkpoints, and the history of the blockchain *before* them cannot be reverted, i.e., if a node receives a block conflicting with a weak subjectivity checkpoint, then it immediately rejects that block.

<details><summary>Weak Subjectivity</summary>

Any `Checkpoint` object can be used as a weak subjectivity checkpoint. These are distributed by providers, downloaded by users and/or distributed as a part of clients, and used as input while syncing a client.

```python

def get_latest_weak_subjectivity_checkpoint_epoch(state, safety_decay=0.1):
    # Returns the epoch of the latest weak subjectivity checkpoint for the given 
    # `state` and `safety_decay`. The default `safety_decay` used should be 10% (= 0.1)
    
    # The calculations in this document do not account for the withdrawability delay.
    # We should factor that in by adding MIN_VALIDATOR_WITHDRAWABILITY_DELAY to the
    # calculated subjectivity period.
    weak_subjectivity_mod = MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    
    val_count = len(get_active_validator_indices(state, get_current_epoch(state)))
    if val_count >= MIN_PER_EPOCH_CHURN_LIMIT * CHURN_LIMIT_QUOTIENT:
        weak_subjectivity_mod += 256 * ((safety_decay*CHURN_LIMIT_QUOTIENT/2) // 256)
    else:
        # This means val_count < MIN_PER_EPOCH_CHURN_LIMIT * CHURN_LIMIT_QUOTIENT
        weak_subjectivity_mod += 256 * ((safety_decay*val_count/(2*MIN_PER_EPOCH_CHURN_LIMIT)) // 256)
    
    return state.finalized_checkpoint.epoch - (state.finalized_checkpoint.epoch % weak_subjectivity_mod)

```

</details>

Two important notions in the context of weak subjectivity are the following.

* **Weak subjectivity period**: *the number of recent epochs within which there must be a weak subjectivity checkpoint to ensure that an attacker who takes control of the validator set at the beginning of the period is slashed at least a minimum threshold in the event that a conflicting checkpoint is finalized*; and
* **Safety decay $D$**: *the loss in the 1/3rd consensus safety margin of the FFG Casper mechanism because of the changing validator set. The new safety margin that the mechanism can tolerate becomes $\frac{1}{3} - D$.* [https://notes.ethereum.org/@adiasg/weak-subjectvity-eth2]


<details><summary>Weak Subjectivity Period</summary>

```python

def compute_weak_subjectivity_period(state: BeaconState) -> uint64:
    """
    Returns the weak subjectivity period for the current ``state``. 
    This computation takes into account the effect of:
        - validator set churn (bounded by ``get_validator_churn_limit()`` per epoch), and 
        - validator balance top-ups (bounded by ``MAX_DEPOSITS * SLOTS_PER_EPOCH`` per epoch).
    A detailed calculation can be found at:
    https://github.com/runtimeverification/beacon-chain-verification/blob/master/weak-subjectivity/weak-subjectivity-analysis.pdf
    """
    ws_period = MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    N = len(get_active_validator_indices(state, get_current_epoch(state)))
    t = get_total_active_balance(state) // N // ETH_TO_GWEI
    T = MAX_EFFECTIVE_BALANCE // ETH_TO_GWEI
    delta = get_validator_churn_limit(state)
    Delta = MAX_DEPOSITS * SLOTS_PER_EPOCH
    D = SAFETY_DECAY

    if T * (200 + 3 * D) < t * (200 + 12 * D):
        epochs_for_validator_set_churn = (
            N * (t * (200 + 12 * D) - T * (200 + 3 * D)) // (600 * delta * (2 * t + T))
        )
        epochs_for_balance_top_ups = (
            N * (200 + 3 * D) // (600 * Delta)
        )
        ws_period += max(epochs_for_validator_set_churn, epochs_for_balance_top_ups)
    else:
        ws_period += (
            3 * N * D * t // (200 * Delta * (T - t))
        )
    
    return ws_period

```

```python

def is_within_weak_subjectivity_period(store: Store, ws_state: BeaconState, ws_checkpoint: Checkpoint) -> bool:
    # Clients may choose to validate the input state against the input Weak Subjectivity Checkpoint
    assert ws_state.latest_block_header.state_root == ws_checkpoint.root
    assert compute_epoch_at_slot(ws_state.slot) == ws_checkpoint.epoch

    ws_period = compute_weak_subjectivity_period(ws_state)
    ws_state_epoch = compute_epoch_at_slot(ws_state.slot)
    current_epoch = compute_epoch_at_slot(get_current_slot(store))
    return current_epoch <= ws_state_epoch + ws_period

```

</details>

Calculating the weak subjective period, as reported by [Aditya Asgaonkar](https://notes.ethereum.org/@adiasg/weak-subjectvity-eth2), results in the following table.


![](https://storage.googleapis.com/ethereum-hackmd/upload_f2d25c1d3fc05f8653d90cc8ed5f45a4.png)


For example, assuming a validator set of at least $262144$ validators and a safety decay of $10\%$, the maximum safe weak subjectivity period is of $3277$ epoch, i.e., around two weeks. In other terms, within two weeks a weak subjectivity checkpoint must be defined. 


*So what would a world powered by weakly subjective consensus look like? First of all, nodes that are always online would be fine; in those cases weak subjectivity is by definition equivalent to objectivity. Nodes that pop online once in a while, or at least once every $N$ blocks, would also be fine, because they would be able to constantly get an updated state of the network. However, new nodes joining the network, and nodes that appear online after a very long time, would not have the consensus algorithm reliably protecting them. Fortunately, for them, the solution is simple: the first time they sign up, and every time they stay offline for a very very long time, they need only get a recent block hash from a friend, a blockchain explorer, or simply their software provider, and paste it into their blockchain client as a checkpoint. They will then be able to securely update their view of the current state from there.* [https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity]


### Problems and Solutions

#### Problem: Balancing attack

[Neu *et al.*](https://arxiv.org/pdf/2009.04987.pdf) [https://ethresear.ch/t/a-balancing-attack-on-gasper-the-current-candidate-for-eth2s-beacon-chain/8079] have shown how the original version of Gasper, i.e., the one presented in the [first part](/GgixO3A1TrSBTfif1E8etw), suffers from a liveness issue that leads to loss of safety for the dynamically available ledger. They presented an attack against Gasper, called *balancing attack*, in the synchronous network model with adversarial network delay.

*Recall that Gasper proceeds in epochs which are further subdivided into $C$ slots each. For simplicity, let $C$ divide $n$ so that every slot has a committee of size $\frac{n}{C}$. For each epoch, a random permutation of all $n$ validators assigns validators to slots’ committees and designates a proposer per slot. Per slot, the proposer produces a new block extending the tip determined by the fork choice rule $HLMD(G)$ executed in local view $G$. Then, each validator of the slot’s committee decides what block to vote for using $HLMD(G)$ in local view $G.$*
*For the Casper FFG layer, a block can only become finalized if two-thirds of validators vote for it. The attacker aims to keep honest validators split between two options (left and right chain) indefinitely, so that neither option ever gets two-thirds votes and thus no block ever gets finalized. Key technique to maintain this split is that some adversarial validators (‘swayers’) withhold their votes and release them only at specific times and to specific subsets of honest nodes in order to influence the fork choice of honest nodes and thus steer which honest nodes vote left/right.* [https://arxiv.org/pdf/2009.04987.pdf]

The attacks requires an adversary to (i) know at what points in time honest validators execute HLMD-GHOST and (ii) be able to target a message for delivery to an honest validator just before a certain point in time. Moreover, it assumes that (iii) honest validators cannot *quickly* update each other about messages they have just received.

The adversary waits until the the proposer in the first slot of an epoch is Byzantine and there are at least six Byzantine validators in every slot of the epoch. Let us assume that this is the case in epoch $0$. The Byzantine proposer of slot $0$ *equivocates* and produces two conflicting blocks (left/blue and right/yellow) which it reveals to two suitably chosen equal-sized subsets of the committee. One subset votes left, the other subset votes ‘right’, obtaining a tie.


![](https://storage.googleapis.com/ethereum-hackmd/upload_7fdc673bd0c56aa55b5c5d40c9ebbfd5.png)


Observe that if the number of honest validator is not even, then the adversary recruits a Byzantine validator ($d$) to behave like an honest one. Finally, all blocks are delivered to every validator before $\Delta$. Note that the only Byzantine validators that cast a vote for slot $0$ are only $a$ and $d$. 

At this point, the adversary selectively releases withheld votes (from Byzantine validators ($c$)) from slot $0$ to split validators of slot $1$ into two groups of equal size, one which sees left\blue as leading and votes for it, and one which sees right/yellow as leading and votes for it, reaching again a tie.

![](https://storage.googleapis.com/ethereum-hackmd/upload_2e5c52361f6814245cac5ac4731753ac.png)

The adversary continues this strategy to maintain the tie throughout epoch $0$.

During epoch $1$, the adversary selectively releases additional withheld votes from epoch $0$ ($b$) to keep splitting validators into two groups, one of which sees left/blue as leading, the other sees right/yellow as leading, voting left/blue and right/yellow, respectively.

![](https://storage.googleapis.com/ethereum-hackmd/upload_50f2c19ea13eae2f44129fe7bb9371e0.png)

Finally, for epoch $2$ and beyond the adversary repeats its actions of epoch $1$. This continues indefinitely preventing finalization. Hence, Gasper is not secure in the synchronous model. 

#### (Part Of The) Solution: Proposer Weight Boosting

The balancing attack just presented is based on the fact that an attacker, by manipulating the network, can create a disagreement at the end of each slot regarding which messages count for the fork choice, and therefore a disagreement on which chain is the winning chain.

[The proposed solution](https://notes.ethereum.org/@vbuterin/lmd_ghost_mitigation) to avoid the balancing attack is to increase the *attestation weight* of the proposer of a block in a given slot, if some conditions are met. In details, let us assume that all the attesters assigned to slot 
$i$, i.e., validators in the committee that cast attestations in slot $i$, have collective total weight $W$. Then, the proposer in slot $i+1$ is expected to make a proposal immediately at the start of its slot. Its proposal implicitly chooses a particular chain. In this way, attesters of slot $i+1$, if they see the proposal arriving before $\frac{1}{3}$ of the way into a slot, they treat that proposal as equivalent to an attestation with weight $\frac{W}{4}$. Observe that this attestation weight for the proposer is valid only for slot $i+1$; after that, this weight is reverted.

<details><summary>Proposer Boosting</summary>

Proposer LMD Score Boosting: [https://github.com/ethereum/consensus-specs/pull/2730]

```python
def on_block(store: Store, signed_block: SignedBeaconBlock) -> None:

...
    
    # Add proposer score boost if the block is timely
    time_into_slot = (store.time - store.genesis_time) % SECONDS_PER_SLOT
    is_before_attesting_interval = time_into_slot < SECONDS_PER_SLOT // INTERVALS_PER_SLOT
    if get_current_slot(store) == block.slot and is_before_attesting_interval:
        store.proposer_boost_root = hash_tree_root(block)

...
```
Recall that `on_block` runs whenever a `SignedBeaconBlock` is received, updating the `store` for the fork choice rule.

</details>


#### Problem: A Balancing Attack Despite Proposer Weight Boosting

Despite the proposer weight boosting solution presented above, [Neu *et al.*](https://arxiv.org/pdf/2203.01315.pdf) have shown that the LMD aspect of HLMD-GHOST still enables balancing attacks to Gasper.

LMD is devised as it follows. Every validator has a local table of the latest message that it received from each other validator, and that can be updated if some conditions are met. In particular, when a validator $v_i \in \mathcal{V}$ receives a valid message (i.e., a vote) from another validator $v_j \in \mathcal{V}$, then the latest message table entry for $v_j$ is updated if and only if new vote of $v_j$ is from a slot *strictly later* than the current latest message table entry. Thus, if $v_i$ observes two equivocating votes from $v_j$ for the same slot, validator $v_i$ considers the vote from $v_j$ received earlier in time. [https://ethresear.ch/t/balancing-attack-lmd-edition/11853]

We present the example showing the attack presented by Neu *at al.* Let $W=100$ be the number of total validators per slot and let us assume that the proposal weight is $W_p = 0.7 W = 70$. Moreover, let us assume a fraction of Byzantine validators of $20\%$, i.e., we assume $20$ Byzantine validators in each slot. Finally, the attack starts when there are five consecutive slots with Byzantine proposers.

During the first four slots the Byzantine proposers create two parallel chains of $4$ blocks each. These chains are initially kept private from the honest validators. The $20$ Byzantine validators vote on each of the $4$ blocks in each slot, i.e., they equivocate. 

 For the fifth slot, the adversary includes all equivocating votes for the left and the right chains into two distinct blocks and attaches these blocks on the left and right chains, respectively. Then, it releases the two equivocating blocks from the fifth slot in such a way that roughly half of the honest validators see the left block first (let us call $L$ that set of honest validators) and with it all the equivocating votes for the left chain; and half of the honest validators see the right block first (let us call $R$ that set of honest validators) and with it all the equivocating votes for the right chain. 

![](https://storage.googleapis.com/ethereum-hackmd/upload_852ffd1c638fe0de41a35bc6c5548b54.png)


Honest validators in $L$ and $R$ believe that their chain (left and right, respectively) has $80$ votes, while the other has $0$ (this because votes that arrive later are not considered, due to LMD). 

If now we assume that slot $6$ has an honest validator $v_i \in L$, then $v_i$ proposes a block extending the left chain. The left chain gains a (temporary) proposal boost equivalent to $70$ votes (recall that we assumed $W_p = 0.7W$). Thus, validators belonging to $L$ see the left chain as leading with 
$150$ votes and vote for it. Conversely, validators belonging to $R$ see the left chain with $70$ votes while the right chain with $80$ votes. Thus they vote for the right chain.

At the end of slot $6$, the proposer boost disappears. In the view of each honest validator, both chains gained roughly the same amount of votes, namely half of the honest validators’ votes. Assuming $|L|=|R|=40$, the proportion of votes between the left chain and the right chain is $120:40$ from the view of validators in $L$, and $40:120$ from the view of validators in $R$.

So, this repeats in subsequent slots, with the honest validators in $L$ and $R$ voting for the left and right chains, respectively.

It is worth noting that, by assumption, if a message is received by an honest validator, then this message will be received also by every other honest validator. This implies that honest validators in $L$ will receive all the messages that honest validators in $R$ received, and vice-versa. So, Byzantine validators that equivocate will eventually be slashed. However, this does not prevent the attack to be placed.

#### (Other Part Of The) Solution: Equivocation Discounting

*Equivocations are attributable faults, punishable by slashing a posteriori, but this does not prevent the attack vector a priori given that only one validator is required for it, and that there is no immediate recovery, because the same validator can continue producing equivocating attestations in subsequent slots as well.* [https://arxiv.org/pdf/2209.03255.pdf]

We present the notion of *equivocation discounting*, a solution to the attack presented in the section right above. On a high level, with equivocation discounting, we rely on every validator eventually recognizing equivocations and discarding them by stopping to give them weight. Formally, we require:

* **Fork choice discounting**: When a validator $v_i$ runs HLMD-GHOST at slot $t$, it only counts votes from eligible validators $v_j$s for which the view of $v_i$ contains at most a single vote for each slot $v_j$s voted for, i.e., which are not viewed to have equivocated at previous slots.

In other words, we discard equivocating attestations from the fork choice, and *discount*, i.e., do not consider the weight of, all future votes of equivocating validators for fork choice purposes. Together with the LMD rule, the protocol considers only each validator’s most recent vote (or *attestation*) and, among them, only the non-equivocating ones. 

Finally, observe that if a Byzantine validator $v_i$ equivocates, eventually every honest validator will have evidence that $v_i$ equivocated. This implies that, eventually, every equivocating validator $v_i$ will be *discovered* by every honest validator, and these equivocations will be used to slash $v_i$.

<details><summary>Equivocation Discounting</summary>

Remove equivocating validators from fork choice consideration: [https://github.com/ethereum/consensus-specs/pull/2845]


```python
def on_attestation(store: Store, attestation: Attestation, is_from_block: bool=False) -> None:

...

    # Update latest messages for attesting indices
    update_latest_messages(store, indexed_attestation.attesting_indices, attestation)
```

with `update_latest_message` defined as


```python
def update_latest_messages(store: Store, attesting_indices: Sequence[ValidatorIndex], attestation: Attestation) -> None:
    target = attestation.data.target
    beacon_block_root = attestation.data.beacon_block_root
    non_equivocating_attesting_indices = [i for i in attesting_indices if i not in store.equivocating_indices]
    for i in non_equivocating_attesting_indices:
        if i not in store.latest_messages or target.epoch > store.latest_messages[i].epoch:
            store.latest_messages[i] = LatestMessage(epoch=target.epoch, root=beacon_block_root)
```


```python

def on_attester_slashing(store: Store, attester_slashing: AttesterSlashing) -> None:
    """
    Run ``on_attester_slashing`` immediately upon receiving a new ``AttesterSlashing``
    from either within a block or directly on the wire.
    """
    attestation_1 = attester_slashing.attestation_1
    attestation_2 = attester_slashing.attestation_2
    assert is_slashable_attestation_data(attestation_1.data, attestation_2.data)
    state = store.block_states[store.justified_checkpoint.root]
    assert is_valid_indexed_attestation(state, attestation_1)
    assert is_valid_indexed_attestation(state, attestation_2)

    indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices)
    for index in indices:
        store.equivocating_indices.add(index)
```

This function updates `store.equivocating_indices` with the validators that cast equivocating votes.


</details>

#### Problem: Avalanche Attack (solved with equivocation discounting)

The [Avalanche Attack](https://arxiv.org/pdf/2203.01315.pdf) is an attack at proof-of-stake GHOST that combines selfish mining with equivocations. Observe that this attack is possible because of the assumed underlying proof-of-stake mechanism. Proof-of-work does not have equivocations. The attack exploits the fact that the weight of a block in GHOST is given by the number of ancestors that such block has. This differs from the *vote-based* variant of GHOST as used in PoS Ethereum, *where block weight is determined by votes and potentially a proposal boost*. [https://arxiv.org/pdf/2203.01315.pdf] However, a similar attack exists also in the vote-based paradigm. Finally, note that *only* [GHOST](https://eprint.iacr.org/2013/881.pdf) is considered, because its variant with LMD does not suffer from this attack. 

 *The adversary uses withheld blocks to displace an honest chain once it catches up in subtree weight with the number of withheld adversarial blocks. The withheld blocks are released in a flat but wide subtree, exploiting the fact that under the GHOST rule such a subtree can displace a long chain. Only two withheld blocks enter the canonical chain permanently, while the other withheld blocks can subsequently be reused (through equivocations) to build further subtrees to displace even more honest blocks. The attack exploits a specific weakness of the GHOST rule in combination with equivocations from PoS, namely that an adversary can reuse ‘uncle blocks’ in GHOST, and thus such equivocations contribute to the weight of multiple ancestors. Formal security proof of PoS GHOST seems doomed.* https://ethresear.ch/t/avalanche-attack-on-proof-of-stake-ghost/11854


We present the example showing the attack presented by Neu *at al.* Let us assume that the adversary starts with $k=6$ withheld blocks and does not gain any new blocks during the attack, meaning that the attack eventually stops. Observe that the larger the number of blocks that are withheld, the longer will the attack last.


First, the adversary withholds its subtree of $k=6$ withheld blocks, while honest nodes produce a chain. (In the figure below, red blocks are blocks from the adversary, while the green blocks constitute the honest chain.) 



![](https://storage.googleapis.com/ethereum-hackmd/upload_9b8ff0f8c718559242c3fde8f5da1bf6.png)





Once honest nodes reach a chain of length $6$, the adversary releases the withheld blocks. Observe that the main chain according to GHOST changes.

![](https://storage.googleapis.com/ethereum-hackmd/upload_6b7176b797e8ea6be27447d0f14a5eb5.png)



Note that the adversary can reuse blocks $3,4,5$ and $6$, in the form of equivocations, on top of the chain $B_{\text{genesis}} → 1 → 2$ formed by the first two withheld adversarial blocks, which is now the chain adopted by honest nodes. Again, once that new chain reaches length $4$, the adversary releases another subtree and, according to GHOST, the main chain changes again.  Once the new chain reaches length $2$, the adversary releases the last displacing subtree. 

Honest nodes now build on $6 \rightarrow 5 \rightarrow 4 \rightarrow 3 \rightarrow 2 \rightarrow 1 \rightarrow B_{\text{genesis}}$. All honest nodes so far have been displaced.

![](https://storage.googleapis.com/ethereum-hackmd/upload_8471a94e1ff220ca780db1f60be2686b.png)

Observe that, through equivocation discounting, this attack can no longer be placed. Equivocating blocks are not considered during the fork choice.

#### Problem: Ex-Ante Reorg

A reorg is an event where a block that was part of the canonical chain becomes no longer part of the canonical chain because a competing block beat it out. Reorgs can occur naturally due to network latency (also called *short reorgs*), or maliciously. In the first case, let us consider for example the proof-of-work. Here, if two miners create blocks $A$ and $A'$ at nearly the same time, then the network partitions with some honest nodes mining on top of $A$ and some mining on top of $A'$. If a new block $B$ is mined as a child of $A$ before any blocks are mined as a child of $A'$, then the network will see $A$ as the tip of the chain, making $A'$ *orphaned*. Every honest miner who saw $A'$ as the tip of the chain, switches to $A$ and deletes block $A'$ from the canonical chain.
The maliciously occurrency of reorgs are instead caused by an adversary who seeks to exploit reorgs for its own gain. This enables attacks like double-spending or front-running.  
Reorgs can be classified in two categories: *ex post reorgs*, i.e., an adversary observes a block which subsequently attempts to fork out, and *ex ante reorgs*, i.e., an adversary attempts to fork out a future block that is unknown to the adversary at the start of the attack.

*Finality is a situation where a fork choice rule so strongly favors a block that it is mathematically impossible, or economically infeasible for that block to get reorged. In some fork choice rules, reorgs cannot happen; the fork choice rule simply extends the existing chain by appending any blocks that have been finalized through consensus. In other fork choice rules, reorgs are very frequent.* [https://www.paradigm.xyz/2021/07/ethereum-reorgs-after-the-merge]

![](https://storage.googleapis.com/ethereum-hackmd/upload_5a39c227f23713121e7e5a8f59e04d95.png)


With Gasper, *long reorgs*, i.e., reorgs that aim to fork out several blocks, are not possible because all blocks that are deeper than $2$ epochs in the past are considered finalized (see FFG Casper and Gasper sections). Moreover, ex post reorgs become practically impossible because an adversary controlling only a few validators has no way to beat the honest majority of thousands of attesters (https://beaconcha.in/validators). In other terms, making a reorg directly requires the attacker to control close to $50\%$ of all validators.

We present a simple ex ante reorgs where an adversary, being the proposer for slot $n+1$, can perform a reorg of one block. Observe that this attack is done on the available ledger $𝖫𝖮𝖦_{\text{da}}$ (see Properties of Gasper section), and assuming synchrony. 


![](https://storage.googleapis.com/ethereum-hackmd/upload_87bd96ae2d1150098899d02673cdc33a.png)


*In slot $n + 1$ the adversary privately creates block $n + 1$ on block $n$ and attests to it. Honest validators of slot $n+1$ do not see any block and thus attest to block $n$ as head of the chain. In the next slot, an honest proposer publishes block $n + 2$ building on block $n$, which is the current head in their view. Simultaneously, the adversary finally publishes block $n + 1$ and the attestation voting for block $n + 1$. All honest validators of slot $n + 2$ attest to block $n + 1$ as head of the chain, because it has more weight than block $n + 2$. In the next slot block $n + 3$ is proposed building on block $n + 1$. Block $n + 2$ is reorged out.* [https://eprint.iacr.org/2021/1413.pdf]


*Proposer boosting does not mitigate all ex ante reorgs* [https://ethresear.ch/t/change-fork-choice-rule-to-mitigate-balancing-and-reorging-attacks/11127]. Let $W=100$ be the number of total validators per slot and let us assume that the proposal weight is $W_p = 0.8 W = 80$. Moreover, let us assume a fraction of Byzantine validators of $7\%$, i.e., we assume $7$ Byzantine validators in each slot.  The attack works as it follows. The adversary proposes a hidden block for the slot $n+1$ and votes for it with $7\%$ of adversarial attestations from that slot. Thus, an honest proposer for slot $n+2$ builds its block on block $n$ (observe that block $n+2$ is now sibling of the hidden block $n+1$). Due to proposer boosting, the $93$ honest validators for slot $n+2$ vote for block $n+2$. However, the adversary again uses its $7\%$ attestations from slot $n+2$ to vote for the hidden block $n+1$.
Now, let us assume that block $n+3$ is also adversarial, and builds on $n+1$. Now the chain of block $n+1$ has $7\%$ attestations from slot $n+1$, $7\%$ attestations from slot $n+2$, and $80\%$ attestations from slot $n+3$ (due to the proposer boosting). This equals $94\%$, which is more than the $93\%$ from the honest committee of slot $n+2$. As a result, honest validators switch over and vote for block $n+3$, and block $n+2$ is forked out.

#### View-Merge As A Replacement For Proposer Weight Boosting

The notion of *view-merge*, initially introduced by the [Highway protocol](https://blog.casperlabs.io/the-casper-network-highway-consensus-protocol/), aims to solve some problems that arise with the proposer boosting technique. For example, proposer boosting can be weaponized by Byzantine proposers to conclude a reorg, lowering the amount of attestations needed for it by the weight of boost. [https://ethresear.ch/t/change-fork-choice-rule-to-mitigate-balancing-and-reorging-attacks/11127]

The idea behind the view-merge is to join the view of the honest proposer with those of all the other honest validators before they cast a vote in their slot. The result is that *in slots with a honest proposer all honest validators vote in favor of the honest proposal.* [https://arxiv.org/pdf/2209.03255.pdf]

The general concept of view-merge is the [following](https://ethresear.ch/t/view-merge-as-a-replacement-for-proposer-boost/13739):

* Attesters freeze their view $\Delta$ seconds before the beginning of a new slot, caching new messages for later processing. (*Note that, currently, the duration of a slot in Gasper is $3\Delta$, with $\Delta$ be the message delay. In particular, the slot is divided into $3$ parts of $4$ seconds each: $4$ seconds to propose a block, $4$ seconds to attest, and $4$ seconds to aggregate the attestations.*)
* The proposer, instead, does not freeze its view, and proposes, based on its view, on top of the head of the chain at the beginning of its slot. Moreover, the proposer references all attestations and blocks it used in its fork choice in some point-to-point message, which is propagated with the block.
* Attesters include the referenced attestations in their view, and attest based on the *merged view*.

If the network delay is less that $\Delta$, then every honest validator receives all the same messages. This implies that the view of the proposer is a superset of the frozen views of other validators. So, the final merged view is equal to the view of the proposer. Moreover, if the output of the fork choice is a function of a view, then every honest validator has the same fork choice output. As a consequence, honest validators attest to honest proposals. 


##### Goldfish

In this section we present [Goldfish](https://arxiv.org/pdf/2209.03255.pdf), a simplified variant of LMD-GHOST, introduced by D'Amato *et al.*, that implements the notions of view-merge and equivocation discounting. Goldfish can tolerate dynamic participation, it supports subsampling of validators (at each slot, the protocol can pseudo-randomly select a small group of validators to run the protocol on behalf of the total validator set), and it is provably secure and reorg resilient in synchronous networks with dynamic participation, assuming a majority of the validators follows the protocol honestly. Finally, Goldfish implements the notion of *vote expiry*, i.e., during each slot only votes from the immediately preceding slot influence the protocol’s behavior.

Goldfish implements a variant of GHOST, for the fork choice rule, called **GHOST-Eph**. GHOST-Eph is a function that *takes a view $G$ and slot $t$ as input, and finds the canonical GHOST-Eph chain determined by the votes within $G$ that were cast for slot $t$. More specifically, starting at the genesis block, the function iterates over a sequence of blocks from $G$, selecting as the next block, the child of the current block with the maximum number of validators that have cast a slot $t$ vote for a block within its subtree. This continues until it reaches a leaf of the block-tree, and outputs a complete chain from leaf to root. The fork choice rule ignores votes from before slot $t$ in its decision (votes are ephemeral), lending GHOST-Eph its name.* [https://arxiv.org/pdf/2209.03255.pdf]

![](https://storage.googleapis.com/ethereum-hackmd/upload_d1fc611e1f14b29644a8b23a3828e09e.png)


*As in Gasper, slots in Goldfish have a duration of $3\Delta$. At the beginning of slot $t$, each awake honest validator $v_i$ checks if it is eligible to propose a block for slot $t$, i.e., if $v_i$ is a leader for slot $t$, by evaluating the verifiable random function (VRF) with secret key $\mathscr{vsk}$. If $v_i$ is the leader for slot $t$, then $v_i$ identifies the tip of its canonical GHOST-Eph chain using the slot $t-1$ votes in its view, and it broadcasts a proposal message containing (i) a new block extending the tip and (ii) the union of its view and buffer, $G \cup \mathcal{B}$.* (Observe that the buffer $\mathcal{B}$ is distinct from the validator’s view $G$, the evergrowing set of messages used to make consensus decisions. Buffered messages are admitted to the view (merged) only at specific points in time.)* *At slot $3\Delta t + \Delta$, among the proposal messages received for slot $t$, each honest awake validator selects the one with the minimum VRF output, and accepts the block contained in the message as the proposal block for slot $t$. Moreover, validator $v_j$ merges its view with that of the proposal message. Then, with its VRF secret key $\mathscr{vsk}$, $v_j$ checks if it is eligible to vote for a block at slot $t$. If that is the case, $v_j$ identifies the new tip of its canonical GHOST-Eph chain using the slot $t − 1$ votes in its updated view, and broadcasts a slot $t$ vote for this tip.*

*At slot $3\Delta t + 2\Delta$, each honest awake validator $v_j$ merges its buffer $\mathcal{B}$ containing the votes received over the period $(3\Delta t + \Delta, 3\Delta t + 2\Delta]$ with its view $G$. Then, $v_j$ identifies the new tip of its canonical GHOST-Eph chain using the slot $t$ votes in its updated view, takes the prefix of this chain corresponding to blocks from slots $\le t-\kappa$, and outputs this confirmed prefix as the Goldfish ledger.*

*At the start of the next slot, i.e., at round $3\Delta t + 3\Delta$, the buffer of any honest validator contains all the votes received by honest validators in the period $(3\Delta t + \Delta, 3\Delta t + 2\Delta]$, i.e., all the votes which they have merged into their view at round $3\Delta t + 2\Delta$. In particular, the proposal message of an honest leader includes all such votes, ensuring that the view in an honest leader’s proposal message is a superset of any honest validator’s views at round $3\Delta(t+1)+\Delta$.* [https://arxiv.org/pdf/2209.03255.pdf]

![](https://storage.googleapis.com/ethereum-hackmd/upload_c63b85c6f554717f29224fed8f6cfab8.png)

A fast confirmation rule can also be added to Goldfish, allowing validators to confirm honest blocks proposed at the tip of their canonical GHOST-Eph chains within the same slot under optimistic conditions, i.e., under high participation and honest supermajority. This is done by adding $\Delta$ more rounds to slots, which are now divided into $4\Delta$ rounds.

![](https://storage.googleapis.com/ethereum-hackmd/upload_0e417531b1f678907f8b644c0f46265f.png)

*At the start of each slot, the proposer merges buffered votes into their local view, determines their canonical chain, and proposes and broadcasts a block extending it, together with their local view. One-fourth into each slot, each voter merges the proposed view into their local view, determines their canonical chain, and casts a vote on the tip. Two-fourths into the slot, all awake validators merge their buffers into their local view and run the optimistic fast confirmation rule.
In particular, at round $4\Delta t + 2\Delta$, a validator merges its buffer and view, then marks a block $B$ proposed at the same slot $t$ as fast confirmed if $G$
contains a subset $G'$ of slot $t$ votes by distinct validators for $B$ such that more than $\frac{3}{4}$ of the eligible voters of slot $t$ voted for $B$. In this case, $B$ and its prefix are output as the Goldfish ledger at round $4\Delta t + 3\Delta$. If no block is fast confirmed $2\Delta$ rounds into a slot in the view of a validator, the validator uses the $\kappa$-slots-deep confirmation rule, i.e., the slow confirmation rule, at round $4\Delta t + 3\Delta$ to output the Goldfish ledger. However, validators do not roll back their ledgers: if the validator has previously fast confirmed a block within the last $\kappa$ slots, it continues to output that block.
Finally, three-fourths into the slot, all awake validators again merge their buffers into their local view, and output a ledger according to GHOST-Eph.* [https://arxiv.org/pdf/2209.03255.pdf]


Goldfish guarantees the following properties, and the proof can be found in the [full paper](https://arxiv.org/pdf/2209.03255.pdf).

* **Reorg resilience**: Suppose the validator that has the proposal with the minimum VRF output within a slot is an honest validator. Then, the block proposed by that validator enters and stays in the canonical GHOST-Eph chain adopted by any honest validator at all future slots.
* **Security**: Goldfish satisfies $T_{\text{conf}}$-security for $T_{\text{conf}} = \kappa$ slots with overwhelming probability.

Observe that $T_{\text{conf}}$ is a polynomial function of a security parameter \kappa$. Moreover, a state machine replication protocol that outputs a ledger $\mathscr{ch}$ is $T_{\text{conf}}$-secure after time $T$, and has transaction confirmation time $T_{\text{conf}}$, if $\mathscr{ch}$ satisfies **Safety** : For any two rounds $t, t′ \ge T$, and any two honest validators $v_i$ and $v_j$ (possibly $i = j$) awake at rounds $t$ and $t′$ respectively, either ledger $\mathscr{ch}_i^t$ is the same as, or a prefix of $\mathscr{ch}_j^{t'}$ or vice-versa; and **Liveness**: If a transaction is received by an awake honest validator at some round $t \ge T$, then for any round $t′ \ge t + T_{\text{conf}}$ and any honest validator $v_i$ awake at round $t'$, the transaction will be included in $\mathscr{ch}_{t'}^i$.

Despite the security guarantees ensured by Goldfish, vote expiry as it is in this protocol leads to some problems. In particular, blocks in Goldfish do not accumulate safety against asynchrony as time goes on. This is because vote expiry after one slot means that *Goldfish cannot tolerate a single slot in which all honest validators are asleep or in which they cannot hear from the other honest validators due to adversarially induced network delay.* [https://arxiv.org/pdf/2209.03255.pdf]

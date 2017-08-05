# ⛼  tinychain

*Putting the rough in "[rough consensus](https://tools.ietf.org/html/rfc7282#section-1)"*


Tinychain is a pocket-sized implementation of Bitcoin. Its goal is to
be the most compact, understandable, and working incarnation of 
[the Nakamoto consensus algorithm](https://bitcoin.org/bitcoin.pdf) at the
expense of functionality, speed, and any real usefulness.

I wrote it primarily to understand Bitcoin better, but hopefully it can serve as
a jumping-off point for programmers who are interested in (but don't have
intimate familiarity with) Bitcoin or cryptocurrency. At the very least, it can
be a piñata for protocol developers who actually know what they're doing.

## Quick start

1. [Install Docker & docker-compose](https://www.docker.com/community-edition#/download)
2. Clone this repo: `git clone git@github.com:jamesob/tinychain.git`
3. Run `docker-compose up`.

This will spawn two tinychain nodes.


## What is Bitcoin?

In very brief terms that map to this code:

Bitcoin is a way of generating pseudo-anonymous, decentralized trust at the cost
of electricity. The most commonly known (but not sole) application of this is as
a currency or store of value. If that sounds abstruse, general, and mindblowing,
that's because it is.

The atomic building block of Bitcoin is the `Transaction`, which assigns some
number of coins to an identity (via `TxOut`s) given some cryptographically
unlocked `TxIn`s.  TxIns must always refer to previously created but unspent
TxOuts.

A Transaction is written into history by being included in a `Block`. Each Block
contains a data structure called a [Merkle
Tree](https://en.wikipedia.org/wiki/Merkle_tree) which generates a fingerprint
unique to the set of Transactions being included. The root of that Merkle tree
is included in the block "header" and hashed (`Block.id`) to permanently seal
the existence and inclusion of each Transaction in the block.

Blocks are linked together in a chain (`active_chain`) by referring to the
previous Block header hash. In order to add a Block to the chain, the contents
of its header must hash to a number under some difficulty target, which is set
based upon how quickly recent blocks have been discovered
(`get_next_work_required()`). This attempts to
normalize the time between block discovery.

When a block is discovered, it creates a subsidy for the discoverer in the form
of newly minted coins. The discoverer also collects fees from transactions
included in the block, which are the value of inputs minus outputs. The block
reward subsidy decreases logarithmically over time.

Nodes in the network are in a never-ending competition to mine and propagate the
next block, and in doing so facilitate the recording of transaction history.
Transactions are submitted to nodes and broadcast across the network, stored
temporarily in `mempool` where they are queued for block inclusion.

For more eloquent, comprehensive descriptions of Bitcoin, see

- [Bitcoin: A Peer-to-Peer Electonic Cash System](https://bitcoin.org/bitcoin.pdf) 
  by Satoshi Nakamoto
- [Mastering Bitcoin](https://github.com/bitcoinbook/bitcoinbook/) by Andreas
  Antonopoulos
- [The Bitcoin Developer Guide](https://bitcoin.org/en/developer-guide)
 

  
## Notable differences from Bitcoin
 
- Byte-level representation and endianness are very important when serializing a
  data structure to be hashed in Bitcoin and are not reproduced
  faithfully here. In fact, serialization of any kind here is very dumbed down
  and based entirely on raw strings or JSON.

- Transaction types are limited to pay-to-public-key-hash (P2PKH), which
  facilitate the bare minimum of "sending money." More exotic
  [transaction
  types](https://bitcoin.org/en/developer-guide#standard-transactions) which 
  allow m-of-n key signatures and
  [Script](https://en.bitcoin.it/wiki/Script)-based unlocking are not
  implemented.

- [Initial Block Download](https://bitcoin.org/en/developer-guide#initial-block-download) 
  is at best a simplified version of the old "blocks-first" scheme. It eschews 
  `getdata` and instead returns block payloads directly in `inv`.

- The longest, valid chain is determined simply by chain length (number of
  blocks) vs. [chainwork](https://bitcoin.stackexchange.com/questions/26869/what-is-chainwork).

- Peer "discovery" is done through environment variable hardcoding. In
  bitcoin core, this is done [with DNS seeds](https://en.bitcoin.it/wiki/Transaction_replacement).

- [Replace by fee](https://en.bitcoin.it/wiki/Transaction_replacement) is absent.

- Memory usage is egregious. Networking is a hack.

- Satoshis are instead called Belushis because, well, who am I kidding anyway.


<img align="right" width=250 src="http://static.rogerebert.com/uploads/blog_post/primary_image/interviews/why-john-belushi-died/primary_EB19840307PEOPLE70926001AR.jpg">
 

## Q&A

### How does RPC work?

We use JSON for over-the-wire serialization. It's slow and unrealistic but
human-readable and easy. We deserialize right into the `.*Msg` classes, 
each of which dictates how a particular RPC message is handled via 
`.handle()`.

### Is this yet another cryptocurrency created solely to Get Rich Quick™?

A resounding Yes! (if you're dealing in the very illiquid currency of 
education)

This thing is basically worthless as a financial system, I have no illusions
about that and neither should you. 

### What's with the logo?

It's a shitty unicode Merkle tree. Give a guy a break here, this is freeware!

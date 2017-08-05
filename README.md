# ⛼  tinychain

*Putting the rough in "[rough consensus](https://tools.ietf.org/html/rfc7282#section-1)"*


Tinychain is a pocket-sized implementation of Bitcoin. Its goal is to
be the most compact, understandable, working incarnation of 
[the Nakamoto consensus algorithm](https://bitcoin.org/bitcoin.pdf) at the
expense of functionality, speed, and any real usefulness.

I wrote it primarily to understand Bitcoin better, but hopefully it can serve as
a jumping-off point for programmers who are interested in (but don't have
intimate familiarity with) Bitcoin or cryptocurrency. At the very least, it can
be a piñata for protocol developers who actually know what they're doing.

```
$ cloc tinychain.py

       1 text file.
       1 unique file.
       0 files ignored.

http://cloc.sourceforge.net v 1.60  T=0.02 s (51.0 files/s, 60859.4 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Python                           1            341            174            679
-------------------------------------------------------------------------------
```

## Quick start

- [Install Docker & docker-compose](https://www.docker.com/community-edition#/download)
- Clone this repo: `git clone git@github.com:jamesob/tinychain.git`
- Run `docker-compose up`. This will spawn two tinychain nodes.
- In another window, run `./bin/sync_wallets`. This brings the wallet data
  from the Docker containers onto your host.
    ```
    $ ./bin/sync_wallets

    Synced node1's wallet:
    [2017-08-05 12:59:34,423][tinychain:1075] INFO your address is 1898KEjkziq9uRCzaVUUoBwzhURt4nrbP8
     0.0 ⛼

    Synced node2's wallet:
    [2017-08-05 12:59:35,876][tinychain:1075] INFO your address is 15YxFVo4EuqvDJH8ey2bY352MVRVpH1yFD
    0.0 ⛼
    ```
- Try running `./client.py balance -w wallet1.dat`; try it with the other
  wallet file.
    ```
    $ ./client.py balance -w wallet2.dat

    [2017-08-05 13:00:37,317][tinychain:1075] INFO your address is 15YxFVo4EuqvDJH8ey2bY352MVRVpH1yFD
    0.0 ⛼
    ```
- Once you see a few blocks go by, try sending some money between the wallets
    ```
    $ ./client.py send -w wallet2.dat 1898KEjkziq9uRCzaVUUoBwzhURt4nrbP8 1337
    
    [2017-08-05 13:08:08,251][tinychain:1077] INFO your address is 1Q2fBbg8XnnPiv1UHe44f2x9vf54YKXh7C
    [2017-08-05 13:08:08,361][client:105] INFO built txn Transaction(...)
    [2017-08-05 13:08:08,362][client:106] INFO broadcasting txn 2aa89204456207384851a4bbf8bde155eca7fcf30b833495d5b0541f84931919
    ```
- Check on the status of the transaction
    ```
     $ ./client.py status e8f63eeeca32f9df28a3a62a366f63e8595cf70efb94710d43626ff4c0918a8a

     [2017-08-05 13:09:21,489][tinychain:1077] INFO your address is 1898KEjkziq9uRCzaVUUoBwzhURt4nrbP8
     Mined in 0000000726752f82af3d0f271fd61337035256051a9a1e5881e82d93d8e42d66 at height 5
    ```


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


### How can I add another RPC command to reveal more data from a node?

Just add a `NamedTuple` subclass with a `handle()` method defined; it registers
automatically. Mimic any existing `*Msg` class.

 
### Why aren't my changes changing anything?

Remember to rebuild the Docker container image when you make changes
```
docker-compose build && docker-compose up
```

### How do I run automated tests?

```
pip install -r requirements.test.txt
py.test --cov test_tinychain.py
```


### Is this yet another cryptocurrency created solely to Get Rich Quick™?

A resounding Yes! (if you're dealing in the very illiquid currency of 
education)

Otherwise nah. This thing has 0 real-world value.


### What's with the logo?

It's a shitty unicode Merkle tree. Give a guy a break here, this is freeware!


### Do you take tips to Get Rich Quick™?

Sure.

![18ehgMUJBqKc2Eyi6WHiMwHFwA8kobYEhy](http://i.imgur.com/KAfUPA6.png)

BTC: `18ehgMUJBqKc2Eyi6WHiMwHFwA8kobYEhy`

Half of all tips will be donated to [an organization providing aid to Syrian refugees](http://www.moas.eu/).

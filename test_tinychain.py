import time

import pytest

import tinychain as t
from tinychain import Block, TxIn, TxOut, Transaction


def test_merkle_trees():
    root = t.get_merkle_root('foo', 'bar')
    fooh = t.sha256d('foo')
    barh = t.sha256d('bar')

    assert root
    assert root.val == t.sha256d(fooh + barh)
    assert root.children[0].val == fooh
    assert root.children[1].val == barh

    root = t.get_merkle_root('foo', 'bar', 'baz')
    bazh = t.sha256d('baz')

    assert root
    assert len(root.children) == 2
    assert root.children[0].val == t.sha256d(fooh + barh)
    assert root.children[1].val == t.sha256d(bazh + bazh)


def test_serialization():
    op1 = t.OutPoint(txid='c0ffee', txout_idx=0)
    op2 = t.OutPoint(txid='c0ffee', txout_idx=1)
    txin1 = t.TxIn(
        to_spend=op1, unlock_sig=b'oursig', unlock_pk=b'foo', sequence=1)
    txin2 = t.TxIn(
        to_spend=op2, unlock_sig=b'oursig', unlock_pk=b'foo', sequence=2)
    txout = t.TxOut(value=101, to_address='1zxoijw')
    txn1 = t.Transaction(txins=[txin1], txouts=[txout], locktime=0)
    txn2 = t.Transaction(txins=[txin2], txouts=[txout], locktime=0)
    block = t.Block(
        1, 'deadbeef', 'c0ffee', int(time.time()), 100, 100, [txn1, txn2])

    for obj in (op1, op2, txin1, txin2, txout, txn1, txn2, block):
        assert t.deserialize(t.serialize(obj)) == obj


def test_build_spend_message():
    txout = t.TxOut(value=101, to_address='1zz8w9')
    txin = t.TxIn(
        to_spend=t.OutPoint('c0ffee', 0),
        unlock_sig=b'oursig', unlock_pk=b'foo', sequence=1)
    txn = t.Transaction(txins=[txin], txouts=[txout], locktime=0)

    spend_msg = t.build_spend_message(
        txin.to_spend, txin.unlock_pk, txin.sequence, txn.txouts)

    assert spend_msg == (
        b'677c2d8f9843d1cc456e7bfbc507c0f6d07d19c69e6bca0cbaa7bfaea4dd840a')

    # Adding a new output to the txn creates a new spend message.

    txn.txouts.append(t.TxOut(value=1, to_address='1zz'))
    assert t.build_spend_message(
        txin.to_spend, txin.unlock_pk, txin.sequence, txn.txouts) != spend_msg


def test_get_median_time_past():
    t.active_chain = []
    assert t.get_median_time_past(10) == 0

    timestamps = [1, 30, 60, 90, 400]
    t.active_chain = [_dummy_block(timestamp=t) for t in timestamps]

    assert t.get_median_time_past(1) == 400
    assert t.get_median_time_past(3) == 90
    assert t.get_median_time_past(2) == 90
    assert t.get_median_time_past(5) == 60


def test_dependent_txns_in_single_block():
    t.active_chain = []
    t.mempool = {}
    t.connect_block(chain1[0])
    t.connect_block(chain1[1])

    assert len(t.active_chain) == 2
    assert len(t.utxo_set) == 2

    utxo1 = t.utxo_set[list(t.utxo_set.keys())[0]]
    txout1 = TxOut(value=901, to_address=utxo1.to_address)
    txin1 = t.make_txin(utxo1.outpoint, txout1)
    txn1 = t.Transaction(txins=[txin1], txouts=[txout1], locktime=0)

    # Create a transaction that is dependent on the yet-unconfirmed transaction
    # above.
    txout2 = TxOut(value=9001, to_address=txout1.to_address)
    txin2 = t.make_txin(t.OutPoint(txn1.id, 0), txout2)
    txn2 = t.Transaction(txins=[txin2], txouts=[txout2], locktime=0)

    # Assert that we don't accept this txn -- too early to spend the coinbase.

    with pytest.raises(t.TxnValidationError) as excinfo:
        t.validate_txn(txn2)
        assert 'UTXO not ready' in str(excinfo.value)

    t.connect_block(chain1[2])

    # Now the coinbase has matured to spending.
    t.accept_txn(txn1)
    assert txn1.id in t.mempool

    # In txn2, we're attempting to spend more than is available (9001 vs. 901).

    assert not t.accept_txn(txn2)

    with pytest.raises(t.TxnValidationError) as excinfo:
        t.validate_txn(txn2)
        assert 'Spend value is more than available' in str(excinfo.value)

    # Recreate the transaction with an acceptable value.
    txout2 = TxOut(value=901, to_address=txout1.to_address)
    txin2 = t.make_txin(t.OutPoint(txn1.id, 0), txout2)
    txn2 = t.Transaction(txins=[txin2], txouts=[txout2], locktime=0)

    t.accept_txn(txn2)
    assert txn2.id in t.mempool

    block = t.assemble_and_solve_block(t.my_address)
    assert t.connect_block(block) == t.ACTIVE_CHAIN_IDX

    assert t.active_chain[-1] == block
    assert block.txns[1:] == [txn1, txn2]
    assert txn1.id not in t.mempool
    assert txn2.id not in t.mempool
    assert t.OutPoint(txn1.id, 0) not in t.utxo_set  # Spent by txn2.
    assert t.OutPoint(txn2.id, 0) in t.utxo_set


def test_pubkey_to_address():
    assert t.pubkey_to_address(
        b'k\xd4\xd8M3\xc8\xf7h*\xd2\x16O\xe39a\xc9]\x18i\x08\xf1\xac\xb8\x0f'
        b'\x9af\xdd\xd1\'\xe2\xc2v\x8eCo\xd3\xc4\xff\x0e\xfc\x9eBzS\\=\x7f'
        b'\x7f\x1a}\xeen"\x9f\x9c\x17E\xeaMH\x88\xec\xf5F') == (
            '18kZswtcPRKCcf9GQsJLNFEMUE8V9tCJr')


def test_reorg():
    t.active_chain = list(chain1)
    t.side_branches = []
    t.mempool = {}
    t.utxo_set = {}
    _add_to_utxo_for_chain(t.active_chain)

    def assert_no_change():
        assert t.active_chain == chain1
        assert t.mempool == {}
        assert [k.txid[:6] for k in t.utxo_set] == [
            '8b7bfc', '844923', 'd07b55']

    assert len(t.utxo_set) == 3

    # No reorg necessary when side branches are empty.

    assert not t.reorg_if_necessary()

    # No reorg necessary when side branch is shorter than the main chain.

    t.side_branches = [chain2[1:2]]

    assert not t.reorg_if_necessary()

    assert t.side_branches == [chain2[1:2]]
    assert_no_change()

    # No reorg necessary when side branch is as long as the main chain.

    t.side_branches = [chain2[1:3]]

    assert not t.reorg_if_necessary()

    assert t.side_branches == [chain2[1:3]]
    assert_no_change()

    # No reorg necessary when side branch is a longer but invalid chain.

    t.side_branches = [chain3_faulty[1:]]

    assert not t.reorg_if_necessary()

    assert t.side_branches == [chain3_faulty[1:]]
    assert_no_change()

    # Reorg necessary when a side branch is longer than the main chain.

    t.side_branches = [chain2[1:3], chain2[1:]]

    assert t.reorg_if_necessary()

    assert [len(c) for c in t.side_branches] == [2, 2]
    # Chain1 was reorged into side_branches.
    assert [b.id for b in t.side_branches[1]] == [b.id for b in chain1[1:]]
    assert t.side_branches == [chain2[1:3], chain1[1:]]
    assert t.mempool == {}
    assert [k.txid[:6] for k in t.utxo_set] == [
        '8b7bfc', '844923', 'd07b55', '8efce2', 'd7a432']


def _add_to_utxo_for_chain(chain):
    for block in chain:
        for tx in block.txns:
            for i, txout in enumerate(tx.txouts):
                t.add_to_utxo(txout, tx, i, tx.is_coinbase, len(chain))


signing_key = t.get_signing_key(
    b'\xf1\xad2y\xbf\xa2x\xabn\xfbO\x98\xf7\xa7\xb4\xc0\xf4fOzX\xbf\xf6\\\xd2\xcb-\x1d:0 \xa7')

chain1 = [
    Block(version=0, prev_block_hash=None, merkle_hash='7118894203235a955a908c0abfc6d8fe6edec47b0a04ce1bf7263da3b4366d22', timestamp=1501646462, bits=22, nonce=1779478, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'0', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),
    Block(version=0, prev_block_hash='000003538ba7723b29ef6073b129ba2a6fac058e3fff0ba245c43b4f2a5d30dc', merkle_hash='e74798a868c8d48a5eca5e726ccc1c80bb7c8ea563f447097ce343180ab59b3c', timestamp=1501646469, bits=22, nonce=1542197, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'1', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),
    Block(version=0, prev_block_hash='000002cc66275ef0c4b3b06313d0373a221ee3dc101b966868524039d52bb782', merkle_hash='abaaf9210225fabd4317133ec2b69f30fcc28f51a5f8e891170cf7362150b34e', timestamp=1501646476, bits=22, nonce=296233, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'2', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)])
]

chain2 = [
    Block(version=0, prev_block_hash=None, merkle_hash='7118894203235a955a908c0abfc6d8fe6edec47b0a04ce1bf7263da3b4366d22', timestamp=1501646462, bits=22, nonce=1779478, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'0', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),
    Block(version=0, prev_block_hash='000003538ba7723b29ef6073b129ba2a6fac058e3fff0ba245c43b4f2a5d30dc', merkle_hash='e74798a868c8d48a5eca5e726ccc1c80bb7c8ea563f447097ce343180ab59b3c', timestamp=1501646698, bits=22, nonce=6337297, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'1', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),
    Block(version=0, prev_block_hash='0000029ba4ef0015f00932e6b959a2ab6b27863fcd119d3b41faf041e18c90fe', merkle_hash='abaaf9210225fabd4317133ec2b69f30fcc28f51a5f8e891170cf7362150b34e', timestamp=1501646727, bits=22, nonce=739810, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'2', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),
    Block(version=0, prev_block_hash='000002e5e363610b1185ffaa6724c30a1dee180d750933605311b0a5d4dfb1aa', merkle_hash='8fa1b95226bc243b950dd213d45d874eab33b42cc63da5bdf3fee3ba89225a60', timestamp=1501646730, bits=22, nonce=1816826, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'3', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),
    Block(version=0, prev_block_hash='0000012c30fcfd60c5f7185d86ce2f0c017d7d77a04cacb849c704f672f01504', merkle_hash='6f0119a3032ed8dc1f288043e9382c51811780c05ec60ef4e0e5faa5396e6869', timestamp=1501646738, bits=22, nonce=2572466, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'4', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),
]

# Make this chain invalid.
chain3_faulty = list(chain2)
chain3_faulty[-2] = chain3_faulty[-2]._replace(nonce=1)


def _dummy_block(**kwargs):
    defaults = dict(
        version=1, prev_block_hash='c0ffee', merkle_hash='deadbeef',
        timestamp=1, bits=1, nonce=1, txns=[])

    return t.Block(**{**defaults, **kwargs})

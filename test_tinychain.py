import time

import pytest
import ecdsa

import tinychain as t
from tinychain import Block, TxIn, TxOut, Transaction
from client import make_txin


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
    utxo = t.UnspentTxOut(
        *txout, txid=txn1.id, txout_idx=0, is_coinbase=False, height=0)
    utxo_set = [utxo.outpoint, utxo]

    for obj in (
            op1, op2, txin1, txin2, txout, txn1, txn2, block, utxo, utxo_set):
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
    assert t.connect_block(chain1[0]) == t.ACTIVE_CHAIN_IDX
    assert t.connect_block(chain1[1]) == t.ACTIVE_CHAIN_IDX

    assert len(t.active_chain) == 2
    assert len(t.utxo_set) == 2

    utxo1 = t.utxo_set[list(t.utxo_set.keys())[0]]
    txout1 = TxOut(value=901, to_address=utxo1.to_address)
    txin1 = make_txin(signing_key, utxo1.outpoint, txout1)
    txn1 = t.Transaction(txins=[txin1], txouts=[txout1], locktime=0)

    # Create a transaction that is dependent on the yet-unconfirmed transaction
    # above.
    txout2 = TxOut(value=9001, to_address=txout1.to_address)
    txin2 = make_txin(signing_key, t.OutPoint(txn1.id, 0), txout2)
    txn2 = t.Transaction(txins=[txin2], txouts=[txout2], locktime=0)

    # Assert that we don't accept this txn -- too early to spend the coinbase.

    with pytest.raises(t.TxnValidationError) as excinfo:
        t.validate_txn(txn2)
        assert 'UTXO not ready' in str(excinfo.value)

    t.connect_block(chain1[2])

    # Now the coinbase has matured to spending.
    t.add_txn_to_mempool(txn1)
    assert txn1.id in t.mempool

    # In txn2, we're attempting to spend more than is available (9001 vs. 901).

    assert not t.add_txn_to_mempool(txn2)

    with pytest.raises(t.TxnValidationError) as excinfo:
        t.validate_txn(txn2)
        assert 'Spend value is more than available' in str(excinfo.value)

    # Recreate the transaction with an acceptable value.
    txout2 = TxOut(value=901, to_address=txout1.to_address)
    txin2 = make_txin(signing_key, t.OutPoint(txn1.id, 0), txout2)
    txn2 = t.Transaction(txins=[txin2], txouts=[txout2], locktime=0)

    t.add_txn_to_mempool(txn2)
    assert txn2.id in t.mempool

    block = t.assemble_and_solve_block(t.pubkey_to_address(
        signing_key.get_verifying_key().to_string()))

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
    t.active_chain = []

    for block in chain1:
        assert t.connect_block(block) == t.ACTIVE_CHAIN_IDX

    t.side_branches = []
    t.mempool = {}
    t.utxo_set = {}
    _add_to_utxo_for_chain(t.active_chain)

    def assert_no_change():
        assert t.active_chain == chain1
        assert t.mempool == {}
        assert [k.txid[:6] for k in t.utxo_set] == [
            '8b7bfc', 'b8a642', '6708b9']

    assert len(t.utxo_set) == 3

    # No reorg necessary when side branches are empty.

    assert not t.reorg_if_necessary()

    # No reorg necessary when side branch is shorter than the main chain.

    for block in chain2[1:2]:
        assert t.connect_block(block) == 1

    assert not t.reorg_if_necessary()
    assert t.side_branches == [chain2[1:2]]
    assert_no_change()

    # No reorg necessary when side branch is as long as the main chain.

    assert t.connect_block(chain2[2]) == 1

    assert not t.reorg_if_necessary()
    assert t.side_branches == [chain2[1:3]]
    assert_no_change()

    # No reorg necessary when side branch is a longer but invalid chain.

    # Block doesn't connect to anything because it's invalid.
    assert t.connect_block(chain3_faulty[3]) is None
    assert not t.reorg_if_necessary()

    # No change in side branches for an invalid block.
    assert t.side_branches == [chain2[1:3]]
    assert_no_change()

    # Reorg necessary when a side branch is longer than the main chain.

    assert t.connect_block(chain2[3]) == 1
    assert t.connect_block(chain2[4]) == 1

    # Chain1 was reorged into side_branches.
    assert [len(c) for c in t.side_branches] == [2]
    assert [b.id for b in t.side_branches[0]] == [b.id for b in chain1[1:]]
    assert t.side_branches == [chain1[1:]]
    assert t.mempool == {}
    assert [k.txid[:6] for k in t.utxo_set] == [
        '8b7bfc', 'b8a642', '6708b9', '543683', '53f3c1']


def _add_to_utxo_for_chain(chain):
    for block in chain:
        for tx in block.txns:
            for i, txout in enumerate(tx.txouts):
                t.add_to_utxo(txout, tx, i, tx.is_coinbase, len(chain))


signing_key = ecdsa.SigningKey.from_string(
    b'\xf1\xad2y\xbf\xa2x\xabn\xfbO\x98\xf7\xa7\xb4\xc0\xf4fOzX\xbf\xf6\\\xd2\xcb-\x1d:0 \xa7',
    curve=ecdsa.SECP256k1)

chain1 = [
    # Block id: 000000154275885a72c004d02aaa9524fc0c4896aef0b0f3bcde2de38f9be561
    Block(version=0, prev_block_hash=None, merkle_hash='7118894203235a955a908c0abfc6d8fe6edec47b0a04ce1bf7263da3b4366d22', timestamp=1501821412, bits=24, nonce=10126761, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'0', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),

    # Block id: 00000095f785bc8fbd6007b36c2f1c414d66db930e2e7354076c035c8f92700b
    Block(version=0, prev_block_hash='000000154275885a72c004d02aaa9524fc0c4896aef0b0f3bcde2de38f9be561', merkle_hash='27661bd9b23552832becf6c18cb6035a3d77b4e66b5520505221a93922eb82f2', timestamp=1501826444, bits=24, nonce=22488415, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'1', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='1Piq91dFUqSb7tdddCWvuGX5UgdzXeoAwA')], locktime=None)]),

    # Block id: 000000f9b679482f24902297fc59c745e759436ac95e93d2c1eff4d5dbd39e33
    Block(version=0, prev_block_hash='00000095f785bc8fbd6007b36c2f1c414d66db930e2e7354076c035c8f92700b', merkle_hash='031f45ad7b5ddf198f7dfa88f53c0262fb14c850c5c1faf506258b9dcad32aef', timestamp=1501826556, bits=24, nonce=30715680, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'2', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='1Piq91dFUqSb7tdddCWvuGX5UgdzXeoAwA')], locktime=None)])
]

chain2 = [
    # Block id: 000000154275885a72c004d02aaa9524fc0c4896aef0b0f3bcde2de38f9be561
    Block(version=0, prev_block_hash=None, merkle_hash='7118894203235a955a908c0abfc6d8fe6edec47b0a04ce1bf7263da3b4366d22', timestamp=1501821412, bits=24, nonce=10126761, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'0', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')], locktime=None)]),

    # Block id: 000000e4785f0f384d13e24caaddcf6723ee008d6a179428ce9246e1b32e3b2c
    Block(version=0, prev_block_hash='000000154275885a72c004d02aaa9524fc0c4896aef0b0f3bcde2de38f9be561', merkle_hash='27661bd9b23552832becf6c18cb6035a3d77b4e66b5520505221a93922eb82f2', timestamp=1501826757, bits=24, nonce=25773772, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'1', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='1Piq91dFUqSb7tdddCWvuGX5UgdzXeoAwA')], locktime=None)]),

    # Block id: 000000a1698495a3b125d9cd08837cdabffa192639588cdda8018ed8f5af3f8c
    Block(version=0, prev_block_hash='000000e4785f0f384d13e24caaddcf6723ee008d6a179428ce9246e1b32e3b2c', merkle_hash='031f45ad7b5ddf198f7dfa88f53c0262fb14c850c5c1faf506258b9dcad32aef', timestamp=1501826872, bits=24, nonce=16925076, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'2', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='1Piq91dFUqSb7tdddCWvuGX5UgdzXeoAwA')], locktime=None)]),

    # Up until this point, we're same length as chain1.

    # This block is where chain3_faulty goes bad.
    # Block id: 000000ef44dd5a56c89a43b9cff28e51e5fd91624be3a2de722d864ae4f6a853
    Block(version=0, prev_block_hash='000000a1698495a3b125d9cd08837cdabffa192639588cdda8018ed8f5af3f8c', merkle_hash='dbf593cf959b3a03ea97bbeb7a44ee3f4841b338d5ceaa5705b637c853c956ef', timestamp=1501826949, bits=24, nonce=12052237, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'3', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='1Piq91dFUqSb7tdddCWvuGX5UgdzXeoAwA')], locktime=None)]),

    # Block id:
    Block(version=0, prev_block_hash='000000ef44dd5a56c89a43b9cff28e51e5fd91624be3a2de722d864ae4f6a853', merkle_hash='a3a55fe5e9f9e5e3282333ac4d149fd186f157a3c1d2b2e04af78c20a519f6b9', timestamp=1501827000, bits=24, nonce=752898, txns=[Transaction(txins=[TxIn(to_spend=None, unlock_sig=b'4', unlock_pk=None, sequence=0)], txouts=[TxOut(value=5000000000, to_address='1Piq91dFUqSb7tdddCWvuGX5UgdzXeoAwA')], locktime=None)])
]

# Make this chain invalid.
chain3_faulty = list(chain2)
chain3_faulty[-2] = chain3_faulty[-2]._replace(nonce=1)


def _dummy_block(**kwargs):
    defaults = dict(
        version=1, prev_block_hash='c0ffee', merkle_hash='deadbeef',
        timestamp=1, bits=1, nonce=1, txns=[])

    return t.Block(**{**defaults, **kwargs})

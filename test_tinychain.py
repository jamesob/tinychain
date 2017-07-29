import time

import tinychain as t

privkey = t.generate_private_key()
pubkey = privkey.get_verifying_key()


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
    op1 = t.OutPoint(txid='c0ffee', output_index=0)
    op2 = t.OutPoint(txid='c0ffee', output_index=1)
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

    spend_msg = t.build_spend_message(txin, txn)

    assert spend_msg == (
        'c6476da1262cb83faf2e2a7e18250aecad0f9b596218f60328535884a0316d46')

    # Adding a new output to the txn creates a new spend message.

    txn.txouts.append(t.TxOut(value=1, to_address='1zz'))
    assert t.build_spend_message(txin, txn) != spend_msg


def test_get_median_time_past():
    assert t.get_median_time_past(10) == 0

    timestamps = [1, 30, 60, 90, 400]
    t.active_chain = [_dummy_block(timestamp=t) for t in timestamps]

    assert t.get_median_time_past(1) == 400
    assert t.get_median_time_past(3) == 90
    assert t.get_median_time_past(2) == 90
    assert t.get_median_time_past(5) == 60


def test_dependent_txns_in_single_block():
    assert False


def test_pubkey_to_address():
    assert t.pubkey_to_address(
        b'k\xd4\xd8M3\xc8\xf7h*\xd2\x16O\xe39a\xc9]\x18i\x08\xf1\xac\xb8\x0f'
        b'\x9af\xdd\xd1\'\xe2\xc2v\x8eCo\xd3\xc4\xff\x0e\xfc\x9eBzS\\=\x7f'
        b'\x7f\x1a}\xeen"\x9f\x9c\x17E\xeaMH\x88\xec\xf5F') == (
            '18kZswtcPRKCcf9GQsJLNFEMUE8V9tCJr')


def _dummy_block(**kwargs):
    defaults = dict(
        version=1, prev_block_hash='c0ffee', merkle_hash='deadbeef',
        timestamp=1, bits=1, nonce=1, txns=[])

    return t.Block(**{**defaults, **kwargs})

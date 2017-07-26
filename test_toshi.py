import time

import ecdsa

import toshi as t

privkey = ecdsa.SigningKey.generate()
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
    op1 = t.OutPoint('c0ffee', 0)
    op2 = t.OutPoint('c0ffee', 1)
    txin1 = t.TxIn(op1, b'oursig', 1)
    txin2 = t.TxIn(op2, b'oursig', 2)
    txout = t.TxOut(101, b'deadbeef')
    txn1 = t.Transaction(txins=[txin1], txouts=[txout], locktime=0)
    txn2 = t.Transaction(txins=[txin2], txouts=[txout], locktime=0)
    block = t.Block(
        1, 'deadbeef', 'c0ffee', int(time.time()), 100, 100, [txn1, txn2])

    for obj in (op1, op2, txin1, txin2, txout, txn1, txn2, block):
        assert t.deserialize(t.serialize(obj)) == obj


def test_pubkey_to_address():
    assert t.pubkey_to_address(
        b'k\xd4\xd8M3\xc8\xf7h*\xd2\x16O\xe39a\xc9]\x18i\x08\xf1\xac\xb8\x0f'
        b'\x9af\xdd\xd1\'\xe2\xc2v\x8eCo\xd3\xc4\xff\x0e\xfc\x9eBzS\\=\x7f'
        b'\x7f\x1a}\xeen"\x9f\x9c\x17E\xeaMH\x88\xec\xf5F') == (
            '18kZswtcPRKCcf9GQsJLNFEMUE8V9tCJr')

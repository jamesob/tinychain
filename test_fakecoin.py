import time

import ecdsa

import fakecoin as fc

privkey = ecdsa.SigningKey.generate()
pubkey = privkey.get_verifying_key()


def test_merkle_trees():
    root = fc.get_merkle_root(['foo', 'bar'])
    fooh = fc.sha256d('foo')
    barh = fc.sha256d('bar')

    assert root
    assert root.val == fc.sha256d(fooh + barh)
    assert root.children[0].val == fooh
    assert root.children[1].val == barh

    root = fc.get_merkle_root(['foo', 'bar', 'baz'])
    bazh = fc.sha256d('baz')

    assert root
    assert len(root.children) == 2
    assert root.children[0].val == fc.sha256d(fooh + barh)
    assert root.children[1].val == fc.sha256d(bazh + bazh)


def test_serialization():
    op1 = fc.OutPoint('c0ffee', 0)
    op2 = fc.OutPoint('c0ffee', 1)
    txin1 = fc.TxIn(op1, b'oursig', 1)
    txin2 = fc.TxIn(op2, b'oursig', 2)
    txout = fc.TxOut(101, b'deadbeef')
    txn1 = fc.Transaction(txins=[txin1], txouts=[txout], locktime=0)
    txn2 = fc.Transaction(txins=[txin2], txouts=[txout], locktime=0)
    block = fc.Block(1, 'deadbeef', int(time.time()), 100, 100, [txn1, txn2])

    for obj in (op1, op2, txin1, txin2, txout, txn1, txn2, block):
        assert fc.deserialize(fc.serialize(obj)) == obj

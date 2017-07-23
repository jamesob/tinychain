"""

Unrealistic simplifications:

- Byte encoding and endianness are very important when serializing a
  data structure to be hashed in Bitcoin and are not reproduced
  faithfully here. In fact, serialization of any kind here is slipshod and
  in many cases relies on implicit expectations about Python builtin
  __repr__ methods.
  See: https://en.bitcoin.it/wiki/Protocol_documentation


- Block `bit` targets are considerably simplified here.
  See: https://bitcoin.org/en/developer-reference#target-nbits

Some shorthand:

- "Tx" stands for "transaction"

TODO:

- Replace-by-fee
- Address generation with RIPEMD160 & base58check per
  https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses

"""
from typing import Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints
import json
import binascii
import hashlib


class Params:
    MAX_BLOCK_SERIALIZED_SIZE = 1000000  # bytes = 1MB


def sha256d(s: Union[str, bytes]) -> str:
    """A double SHA-256 hash."""
    if not isinstance(s, bytes):
        s = s.encode()

    return hashlib.sha256(hashlib.sha256(s).digest()).hexdigest()


def bytes_to_hex_str(b: bytes):
    return binascii.hexlify(b).decode()


# Set of unspent transaction outputs. Maps transaction IDs to TxOut objects.
utxo_set: Dict[str, Iterable['TxOut']] = {}

# Set of yet-unmined transactions.
mempool = set()


# Used to represent the specific output (since a transaction can have many
# outputs) within a transaction.
OutPoint = NamedTuple('OutPoint', [('txn_hash', str), ('output_index', int)])


def serialize(obj):
    def contents_to_primitive(o):
        if hasattr(o, '_asdict'):
            o = {**o._asdict(), '_type': type(o).__name__}
        elif isinstance(o, list):
            return [contents_to_primitive(i) for i in o]
        elif isinstance(o, bytes):
            return o.decode('utf-8')
        elif not isinstance(o, (dict, bytes, str, int)):
            raise ValueError(f"Can't serialize {o}")

        if isinstance(o, Mapping):
            for k, v in o.items():
                o[k] = contents_to_primitive(v)

        return o

    return json.dumps(
        contents_to_primitive(obj), sort_keys=True, separators=(',', ':'))


def deserialize(serialized: str):
    gs = globals()

    def contents_to_objs(o):
        if isinstance(o, list):
            return [contents_to_objs(i) for i in o]
        elif not isinstance(o, Mapping):
            return o

        _type = gs[o.pop('_type', None)]
        bytes_keys = {
            k for k, v in get_type_hints(_type).items() if v == bytes}

        for k, v in o.items():
            o[k] = contents_to_objs(v)

            if k in bytes_keys:
                o[k] = o[k].encode()

        return _type(**o)

    return contents_to_objs(json.loads(serialized))


class TxIn(NamedTuple):
    """Inputs to a Transaction."""
    # A reference to the output we're spending.
    to_spend: OutPoint

    # The signature which unlocks the TxOut for spending.
    unlock_sig: bytes

    # A sender-defined sequence number which allows us replacement of the txn
    # if desired.
    sequence: int


class TxOut(NamedTuple):
    """Outputs from a Transaction."""
    # The number of Belushis this awards.
    value: int

    # The public key of the owner of this Txn.
    pk_script: bytes


class TxnValidationError(Exception):
    pass


class Transaction(NamedTuple):
    txins: Iterable[TxIn]
    txouts: Iterable[TxOut]

    # The block number or timestamp at which this transaction is unlocked.
    # < 500000000: Block number at which this transaction is unlocked.
    # >= 500000000: UNIX timestamp at which this transaction is unlocked.
    locktime: int

    def validate(self, as_coinbase=False):
        """c.f. https://en.bitcoin.it/wiki/Protocol_rules#.22tx.22_messages"""
        if self.serialize() > Params.MAX_BLOCK_SERIALIZED_SIZE:
            raise TxnValidationError('Too big')

        if not self.txins and not as_coinbase:
            raise TxnValidationError('No inputs and not a coinbase txn')


class Block(NamedTuple):
    # A version integer.
    version: int

    # A hash of the previous block's header.
    prev_block: str

    # A UNIX timestamp of when this block was created.
    timestamp: int

    # The difficulty target; i.e. the hash of this block header must be under
    # this value to consider work proved.
    bits: int

    # The value that's incremented in an attempt to get the block header to
    # hash to a value below `bits`.
    nonce: int

    txns: Iterable[Transaction]

    @property
    def header(self) -> str:
        return (
            f"{self.version}{self.prev_block}{self.merkle_root.val}"
            f"{self.timestamp}{self.bits}{self.nonce}")

    @property
    def merkle_root(self):
        return get_merkle_root(self.txns)


class MerkleNode(NamedTuple):
    val: str
    children: Iterable = None


def _chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def get_merkle_root(leaves: Iterable[str]) -> MerkleNode:
    """Builds a Merkle tree and returns the root given some leaf values."""
    if len(leaves) % 2 == 1:
        leaves = leaves + [leaves[-1]]

    def find_root(nodes):
        newlevel = [
            MerkleNode(sha256d(i1.val + i2.val), children=[i1, i2])
            for [i1, i2] in _chunks(nodes, 2)
        ]

        return find_root(newlevel) if len(newlevel) > 1 else newlevel[0]

    return find_root([MerkleNode(sha256d(l)) for l in leaves])

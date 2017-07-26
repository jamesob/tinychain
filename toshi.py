"""

Notes:

- Where sensible, I've used naming which corresponds to bitcoin codebase
  equivalents. This breaks with Python convention but hopefully it makes for
  easier greping through bitcoin should you get curious.

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

- PoW: proof of work
- Tx: transaction

TODO:

- txn signing
- block assembly
- singlet mining
- p2p
- Replace-by-fee
- Address generation with RIPEMD160 & base58check per
  https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses

"""
import time
import json
import binascii
import hashlib
import logging
from functools import lru_cache
from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints, Tuple)

from base58 import b58encode_check


logger = logging.getLogger(__name__)


class Params:
    MAX_BLOCK_SERIALIZED_SIZE = 1000000  # bytes = 1MB

    # Coinbase transaction outputs can be spent after this many blocks have
    # elapsed since being mined.
    COINBASE_MATURITY = 100

    # Accept blocks which timestamped as being from the future up to this
    # amount.
    MAX_FUTURE_BLOCK_TIME = (60 * 60 * 2)

    # The number of Belushis per coin.
    #
    # #bitcoin-name: COIN
    BELUSHIS_PER_COIN = 100e6

    TOTAL_COINS = 21_000_000

    # The maximum number of Belushis that will ever be found.
    MAX_MONEY = BELUSHIS_PER_COIN * TOTAL_COINS

    # The duration we want to pass between blocks being found, in seconds.
    # This is lower than Bitcoin's configuation (10 * 60).
    #
    # #bitcoin-name: PowTargetSpacing
    TIME_BETWEEN_BLOCKS_IN_SECS_TARGET = 2 * 60

    # The number of seconds we want a difficulty period to last.
    #
    # Note that this differs considerably from the behavior in Bitcoin, which
    # is configured to target difficulty periods of (10 * 2016) minutes.
    #
    # #bitcoin-name: PowTargetTimespan
    DIFFICULTY_PERIOD_IN_SECS_TARGET = (60 * 60 * 10)

    # After this number of blocks are found, adjust difficulty.
    #
    # #bitcoin-name DifficultyAdjustmentInterval
    DIFFICULTY_PERIOD_IN_BLOCKS = (
        DIFFICULTY_PERIOD_IN_SECS_TARGET / TIME_BETWEEN_BLOCKS_IN_SECS_TARGET)

    # The number of blocks after which the mining subsidy will halve.
    #
    # #bitcoin-name: SubsidyHalvingInterval
    HALVE_SUBSIDY_AFTER_BLOCKS_NUM = 210_000


# Used to represent the specific output (since a transaction can have many
# outputs) within a transaction.
OutPoint = NamedTuple('OutPoint', [('txn_hash', str), ('output_index', int)])


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


class UnspentTxOut(TxOut):
    # The ID of the transaction this output belongs to.
    txid: str

    # Did this TxOut from from a coinbase transaction?
    is_coinbase: bool

    # The blockchain height this TxOut was included in the chain.
    height: int

    @classmethod
    def from_mempool_txn(cls, txn) -> Iterable['UnspentTxOut']:
        # UTXO contained in mempool can't be a coinbase transaction --
        # otherwise it would have been mined and thus found in `utxo_set`.
        return [
            cls(**i, txid=txn.id, is_coinbase=False, height=-1)
            for i in txn.txouts]


class Transaction(NamedTuple):
    txins: Iterable[TxIn]
    txouts: Iterable[TxOut]

    # The block number or timestamp at which this transaction is unlocked.
    # < 500000000: Block number at which this transaction is unlocked.
    # >= 500000000: UNIX timestamp at which this transaction is unlocked.
    locktime: int

    @property
    def is_coinbase(self) -> bool:
        return not self.txins

    @property
    def id(self) -> str:
        return sha256d(serialize(self))

    def validate_basics(self, as_coinbase=False):
        if (not self.txouts) or (not self.txins and not as_coinbase):
            raise TxnValidationError('Missing txouts or txins')

        if len(serialize(self)) > Params.MAX_BLOCK_SERIALIZED_SIZE:
            raise TxnValidationError('Too large')

        if sum(t.value for t in self.txouts) > Params.MAX_MONEY:
            raise TxnValidationError('Spend value too high')


class Block(NamedTuple):
    # A version integer.
    version: int

    # A hash of the previous block's header.
    prev_block_hash: str

    # A hash of the Merkle tree containing all txns.
    merkle_hash: str

    # A UNIX timestamp of when this block was created.
    timestamp: int

    # The difficulty target; i.e. the hash of this block header must be under
    # this value to consider work proved.
    bits: int

    # The value that's incremented in an attempt to get the block header to
    # hash to a value below `bits`.
    nonce: int

    txns: Iterable[Transaction]

    def header(self, nonce=None) -> str:
        return (
            f'{self.version}{self.prev_block_hash}{self.merkle_hash}'
            f'{self.timestamp}{self.bits}{nonce or self.nonce}')

    @property
    def id(self) -> str:
        return sha256d(self.header())


# Chain
# ----------------------------------------------------------------------------

# The highest proof-of-work, valid blockchain.
#
# #bitcoin-name: chainActive
active_chain: Iterable[Block] = []

# Branches off of the main chain.
side_branches: Iterable[Iterable[Block]] = []


def get_current_height():
    return len(active_chain)


def get_height(block_id: str) -> int:
    for i, block in enumerate(active_chain[::-1]):
        if block.id == block_id:
            return i
    return -1


def find_block(block_id: str, chain=active_chain) -> (Block, int):
    chains = [chain] if chain else [active_chain, *side_branches]

    for chain in chains:
        for i, block in enumerate(chain):
            if block.id == block_id:
                return (block, i)
    return (None, None)


def get_median_time_past(num_last_blocks: int) -> int:
    """Grep for: GetMedianTimePast."""
    last_n_blocks = active_chain[::-1][:num_last_blocks]

    if not last_n_blocks:
        return 0

    return last_n_blocks[len(last_n_blocks) // 2].timestamp


# Proof of work
# ----------------------------------------------------------------------------

def get_next_work_required(prev_block_hash: str) -> int:
    (prev_block, prev_height) = find_block(prev_block_hash, chain=None)

    if (prev_height + 1) % Params.DIFFICULTY_PERIOD_IN_BLOCKS != 0:
        return prev_block.bits

    # #bitcoin-name: CalculateNextWorkRequired
    period_start_block = active_chain[max(
        prev_height - (Params.DIFFICULTY_PERIOD_IN_BLOCKS - 1), 0)]
    actual_time_taken = prev_block.timestamp - period_start_block.timestamp

    if actual_time_taken < Params.DIFFICULTY_PERIOD_IN_SECS_TARGET:
        # Increase the difficulty
        return prev_block.bits / 2
    elif actual_time_taken > Params.DIFFICULTY_PERIOD_IN_SECS_TARGET:
        return prev_block.bits * 2
    else:
        # Wow, that's unlikely.
        return prev_block.bits


def mine(bits: int, block: Block = None):
    start = time.time()
    nonce = 0
    block = block or Block(
        1, 'deadbeef', 'beef', int(time.time()), bits, nonce, [])

    while int(sha256d(block.header(nonce)), 16) >= bits:
        nonce += 1

    block = block._replace(nonce=nonce)
    duration = int(time.time() - start)
    khs = (block.nonce // duration) // 1000
    print(f'block found: {duration} s - {khs} KH/s - {block.id}')


# Validation
# ----------------------------------------------------------------------------


def validate_txn(serialized_txn: str,
                 as_coinbase: bool = False) -> Transaction:
    try:
        txn = deserialize(serialized_txn)
    except Exception:
        logger.exception(f"Couldn't deserialize transaction {serialized_txn}")
        raise TxnValidationError('Couldn not deserialize')

    txn.validate_basics()

    if txn in mempool:
        raise TxnValidationError('Already in mempool')

    available_to_spend = 0

    for i, txin in enumerate(txn.txins):
        if find_with_txin_in_mempool(txin):
            raise TxnValidationError(f'TxIn[{i}] already being used')

        utxo = find_utxo_for_txin(txin)

        if not utxo:
            raise TxnValidationError(
                f'Could find no UTXO for TxIn[{i}] -- orphaning txn',
                to_orphan=txn)

        if utxo.is_coinbase and \
                (get_current_height() - utxo.height) < \
                Params.COINBASE_MATURITY:
            raise TxnValidationError(f'Coinbase UTXO not ready for spend')

        if not validate_signature_for_spend(txin, utxo):
            raise TxnValidationError(
                f'{txin} is not a valid spend of {utxo}')

        available_to_spend += utxo.value

    if available_to_spend < sum(o.value for o in txn.txouts):
        raise TxnValidationError('Spend value is more than available')

    return txn


def validate_signature_for_spend(txin: TxIn, utxo: UnspentTxOut):
    raise NotImplementedError


def validate_block(serialized_block: str) -> Block:
    try:
        block = deserialize(serialized_block)
    except Exception:
        logger.exception(f"Couldn't deserialize block {serialized_block}")
        raise BlockValidationError('Couldn not deserialize')

    if not block.txns:
        raise BlockValidationError('txns empty')

    if block.timestamp - time.time() > Params.MAX_FUTURE_BLOCK_TIME:
        raise BlockValidationError('Block timestamp too far in future')

    if int(block.id, 16) > (1 << block.bits):
        raise BlockValidationError("Block header doesn't satisfy bits")

    if [i for (i, tx) in enumerate(block.txns) if tx.is_coinbase] == [0]:
        raise BlockValidationError('First txn must be coinbase and no more')

    try:
        for txn in block.txns:
            txn.validate_basics()
    except TxnValidationError:
        logger.exception(f"Transaction {txn} in {block} failed to validate")
        raise BlockValidationError('Invalid txn {txn.id}')

    if get_merkle_root(block.txns).val != block.merkle_hash:
        raise BlockValidationError('Merkle hash invalid')

    if not find_block(block.prev_block_hash, chain=None)[0]:
        raise BlockValidationError(
            f'Previous block {block.prev_block_hash} not found in any chain',
            to_orphan=block)

    if get_next_work_required(block.prev_block_hash) != block.bits:
        raise BlockValidationError('bits is incorrect')

    if block.timestamp <= get_median_time_past(11):
        raise BlockValidationError('timestamp too old')


class BaseException(Exception):
    def __init__(self, msg):
        self.msg = msg


class TxnValidationError(BaseException):
    def __init__(self, *args, to_orphan: Transaction = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.to_orphan = to_orphan


class BlockValidationError(BaseException):
    def __init__(self, *args, to_orphan: Block = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.to_orphan = to_orphan


# mempool & UTXO set
# ----------------------------------------------------------------------------

# Set of unspent transaction outputs. Maps transaction IDs to TxOut objects.
utxo_set: Dict[str, Iterable[UnspentTxOut]] = {}

# Set of yet-unmined transactions.
mempool: Dict[str, Transaction] = {}


# Set of orphaned (i.e. has inputs referencing yet non-existent UTXOs)
# transactions.
orphan_txns = set()


def find_with_txin_in_mempool(txin):
    for txn in mempool:
        if txin in txn.txins:
            return txn
    return None


def find_utxo_for_txin(txin) -> UnspentTxOut:
    """Search the utxo_set and the mempool for a UTXO corresponding to txin."""
    tx_to_spend_hash = txin.to_spend.txn_hash
    idx = txin.to_spend.output_index
    found_utxos = None
    found_in_utxo = utxo_set.get(tx_to_spend_hash)
    found_in_mempool = mempool.get(tx_to_spend_hash)

    if found_in_utxo:
        found_utxos = found_in_utxo
    elif found_in_mempool:
        found_utxos = UnspentTxOut.from_mempool_txn(found_in_mempool.id)
    else:
        return None

    try:
        return found_utxos[idx]
    except IndexError:
        logger.debug(
            "Transaction %s does not have an output at index %s",
            tx_to_spend_hash, idx)
        return None


# Merkle trees
# ----------------------------------------------------------------------------

class MerkleNode(NamedTuple):
    val: str
    children: Iterable = None


@lru_cache(maxsize=1024)
def get_merkle_root(*leaves: Tuple[str]) -> MerkleNode:
    """Builds a Merkle tree and returns the root given some leaf values."""
    if len(leaves) % 2 == 1:
        leaves = leaves + (leaves[-1],)

    def find_root(nodes):
        newlevel = [
            MerkleNode(sha256d(i1.val + i2.val), children=[i1, i2])
            for [i1, i2] in _chunks(nodes, 2)
        ]

        return find_root(newlevel) if len(newlevel) > 1 else newlevel[0]

    return find_root([MerkleNode(sha256d(l)) for l in leaves])


# Peer-to-peer
# ----------------------------------------------------------------------------

def relay_to_peers(serialized_txn: str):
    raise NotImplementedError


def accept_txn(serialized_txn: str):
    txn = Transaction.validate(serialized_txn)
    mempool[txn.id] = txn
    relay_to_peers(serialized_txn)


# Uninteresting utilities
# ----------------------------------------------------------------------------

def pubkey_to_address(pubkey: bytes) -> str:
    if 'ripemd160' not in hashlib.algorithms_available:
        raise RuntimeError('missing ripemd160 hash algorithm')

    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    print(binascii.hexlify(ripe))
    return b58encode_check(b'\x00' + ripe)


def serialize(obj) -> str:
    """NamedTuple-flavored serialization to JSON."""
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


def deserialize(serialized: str) -> object:
    """NamedTuple-flavored serialization from JSON."""
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


def sha256d(s: Union[str, bytes]) -> str:
    """A double SHA-256 hash."""
    if not isinstance(s, bytes):
        s = s.encode()

    return hashlib.sha256(hashlib.sha256(s).digest()).hexdigest()


def bytes_to_hex_str(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def _chunks(l, n) -> Iterable[Iterable]:
    for i in range(0, len(l), n):
        yield l[i:i + n]

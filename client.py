#!/usr/bin/env python3
"""
⛼  tinychain client

Usage:
  client.py balance [options] [--raw]
  client.py send [options] <addr> <val>
  client.py status [options] <txid> [--csv]

Options:
  -h --help            Show help
  -w, --wallet PATH    Use a particular wallet file (e.g. `-w ./wallet2.dat`)
  -n, --node HOSTNAME  The hostname of node to use for RPC (default: localhost)
  -p, --port PORT      Port node is listening on (default: 9999)

"""
import logging
import os
import socket

from docopt import docopt

import tinychain as t


logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


def main(args):
    args['signing_key'], args['verifying_key'], args['my_addr'] = (
        t.init_wallet(args.get('--wallet')))

    if args['--port']:
        send_msg.port = args['--port']
    if args['--node']:
        send_msg.node_hostname = args['--node']

    if args['balance']:
        get_balance(args)
    elif args['send']:
        send_value(args)
    elif args['status']:
        txn_status(args)


def get_balance(args):
    """
    Get the balance of a given address.
    """
    val = sum(i.value for i in find_utxos_for_address(args))

    print(val) if args['--raw'] else print(
        f"{val / t.Params.BELUSHIS_PER_COIN} ⛼ ")


def txn_status(args):
    """
    Get the status of a transaction.

    Prints [status],[containing block_id],[height mined]
    """
    txid = args['<txid>']
    as_csv = args['--csv']
    mempool = send_msg(t.GetMempoolMsg())

    if txid in mempool:
        print(f'{txid}:in_mempool,,' if as_csv else 'Found in mempool')
        return

    chain = send_msg(t.GetActiveChainMsg())

    for tx, block, height in t.txn_iterator(chain):
        if tx.id == txid:
            print(
                f'{txid}:mined,{block.id},{height}' if as_csv else
                f'Mined in {block.id} at height {height}')
            return

    print(f'{txid}:not_found,,' if as_csv else 'Not found')


def send_value(args: dict):
    """
    Send value to some address.
    """
    val, to_addr, sk = int(args['<val>']), args['<addr>'], args['signing_key']
    selected = set()
    my_coins = list(sorted(
        find_utxos_for_address(args), key=lambda i: (i.value, i.height)))

    for coin in my_coins:
        selected.add(coin)
        if sum(i.value for i in selected) > val:
            break

    txout = t.TxOut(value=val, to_address=to_addr)

    txn = t.Transaction(
        txins=[make_txin(sk, coin.outpoint, txout) for coin in selected],
        txouts=[txout])

    logger.info(f'built txn {txn}')
    logger.info(f'broadcasting txn {txn.id}')
    send_msg(txn)


def send_msg(data: bytes, node_hostname=None, port=None):
    node_hostname = getattr(send_msg, 'node_hostname', 'localhost')
    port = getattr(send_msg, 'port', 9999)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((node_hostname, port))
        s.sendall(t.encode_socket_data(data))
        return t.read_all_from_socket(s)


def find_utxos_for_address(args: dict):
    utxo_set = dict(send_msg(t.GetUTXOsMsg()))
    return [u for u in utxo_set.values() if u.to_address == args['my_addr']]


def make_txin(signing_key, outpoint: t.OutPoint, txout: t.TxOut) -> t.TxIn:
    sequence = 0
    pk = signing_key.verifying_key.to_string()
    spend_msg = t.build_spend_message(outpoint, pk, sequence, [txout])

    return t.TxIn(
        to_spend=outpoint, unlock_pk=pk,
        unlock_sig=signing_key.sign(spend_msg), sequence=sequence)


if __name__ == '__main__':
    main(docopt(__doc__, version='tinychain client 0.1'))

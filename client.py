from typing import NamedTuple
import tinychain as t


signing_key = t.init_wallet()


def make_txin(outpoint, txout):
    sequence = 0
    pk = signing_key.verifying_key.to_string()
    spend_msg = t.build_spend_message(outpoint, pk, sequence, [txout])

    return t.TxIn(
        to_spend=outpoint, unlock_pk=pk,
        unlock_sig=signing_key.sign(spend_msg), sequence=sequence)


class BalanceMsg(NamedTuple):
    addr: str

    def handle(self, sock, peername):
        coins = [u for u in utxo_set.values() if u.to_address == self.addr]
        sock.sendall(str(sum(i.value for i in coins)).encode())


class Send(NamedTuple):
    addr: str
    value: int

    def handle(self, sock, peername):
        selected = set()
        my_coins = list(sorted(
            find_utxos_for_address(my_address),
            key=lambda i: (i.value, i.height)))

        for coin in my_coins:
            selected.add(coin)
            if sum(i.value for i in selected) > self.value:
                break

        txout = TxOut(value=self.value, to_address=self.addr)

        txn = Transaction(
            txins=[make_txin(coin.outpoint, txout) for coin in selected],
            txouts=[txout])

        logger.info(f'submitting to network: {txn}')
        accept_txn(txn)

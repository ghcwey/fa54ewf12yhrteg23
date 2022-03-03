import json
from time import sleep
from threading import Lock, Thread
from eth_account import Account
from web3 import Web3
from datetime import datetime
import secrets
import cloudscraper
from random import choice, randint


node_url = 'https://testnet.aurora.dev'
web3 = Web3(Web3.HTTPProvider(node_url, request_kwargs={'timeout': 200}))


contract = web3.eth.contract(address=web3.toChecksumAddress('0x07937297c4768856c97606e3c2b42824a5d46633'), abi=json.loads('[{"inputs":[{"internalType":"address","name":"_sYETIAddress","type":"address"},{"internalType":"address","name":"_treasuryAddress","type":"address"},{"internalType":"address","name":"_teamAddress","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"domainSeparator","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getDeploymentStartTime","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"isOwner","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"mintTestOnly","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"permitTypeHash","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"sYETIAddress","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_sender","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"sendToSYETI","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"version","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}]'))
lock = Lock()


def make_transaction(_gas, contract_address, _acc, _data):
    prev_nonce = web3.eth.get_transaction_count(_acc.address)
    tx = dict(
        nonce=prev_nonce,
        gasPrice=0,
        gas=_gas,
        to=web3.toChecksumAddress(contract_address),
        data=_data,
        value=0,
        chainId=web3.eth.chain_id
    )
    signed = web3.eth.account.signTransaction(
        tx, private_key=_acc.privateKey)
    
    try:
        tx = web3.eth.sendRawTransaction(signed.rawTransaction)
        web3.eth.waitForTransactionReceipt(tx, timeout=240, poll_latency=0.5)
        while True:
            sleep(5)
            new_nonce = web3.eth.get_transaction_count(_acc.address)
            if new_nonce > prev_nonce:
                return
    except Exception as e:
        if 'ERR_INCORRECT_NONCE' in str(e):
            sleep(5)
        else:
            raise






    
def a():
    while True:
        _p = secrets.token_hex(32)
        private_key = '0x' + _p
        acc: Account = Account.from_key(private_key)

        try:
            
            while True:
                # get token 0x9f678cca
                try:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #1')
                    make_transaction(
                                6721975, '0xe8b53eE0443620fB8DcEaEB6DE98ED117971c329', acc, '0x9f678cca')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #1 done')
                    break
                except:      
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #1 ERROR')
                    sleep(5)





            while True:
                try:
                    # approve near
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #2')
                    make_transaction(
                        6721975, '0x01b2edff9b095dc270beca46e2efb41a3ecee169', acc, '0x095ea7b3000000000000000000000000910fb0ae51761cccdbbd9ced613e6a4dc571594affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #2 done')
                    break

                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #2 ERROR')
                    sleep(5)




            while True:
                try:
                    # deposit near(mint)
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #3')
                    make_transaction(
                        6721975, '0x910fb0AE51761ccCDBbD9ced613e6A4dc571594a', acc, '0xa0712d68000000000000000000000000000000000000000001750ef6fd5306a2a3000000')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #3 done')
                    break
           
                except:

                            
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #3 ERROR')
                    sleep(5)







            while True:
                try:
                    # approve usdc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #4')
                    make_transaction(
                        6721975, '0xe1db3e2f129539b2399d8cd9e808305c85f0c82f', acc, '0x095ea7b30000000000000000000000007a9984522bc81b348d66379ed36be5bd6147820effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #4 done')
                    break

                except:


                    print(f'{datetime.now()} | [{acc.address}] - Transaction #4 ERROR')
                    sleep(5)

            while True:
                try:
                    # deposit usdc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #5')
                    make_transaction(
                        6721975, '0x7A9984522bC81B348d66379ed36Be5BD6147820E', acc, '0xa0712d680000000000000000000000000000000000000000000000000000000089173700')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #5 done')
                    break

                except:

                    print(f'{datetime.now()} | [{acc.address}] - Transaction #5 ERROR')
                    sleep(5)




            while True:
                try:
                    # approve usdtt
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #6')
                    make_transaction(
                        6721975, '0x4459ed2deffe0569ae748ad5d7cfefdeef667e87', acc, '0x095ea7b3000000000000000000000000dacc02a4ff16ea3c1515adbfdceb7b1f448b79c8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #6 done')
                    break
                    
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #6 ERROR')
                    sleep(5)
            while True:
                try:
                    # deposit usdtt
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #7')
                    make_transaction(
                        6721975, '0xdacc02a4ff16ea3c1515adbfdceb7b1f448b79c8', acc, '0xa0712d680000000000000000000000000000000000000000000000000000000089173700')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #7 done')
                    break

                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #7 ERROR')
                    sleep(5)
            while True:
                try:
                    # approve dai
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #8')
                    make_transaction(
                        6721975, '0x1c9998C7768517b83136d3b237a31bc69eDc9028', acc, '0x095ea7b3000000000000000000000000c337343d1ac9f77b1305261ccd17e3799f088d4bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #8 done')
                    break

                except:

                    print(f'{datetime.now()} | [{acc.address}] - Transaction #8 ERROR')
                    sleep(5)
            while True:
                try:
                    # deposit dai
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #9')
                    make_transaction(
                        6721975, '0xC337343d1ac9F77B1305261CCD17e3799F088D4B', acc, '0xa0712d6800000000000000000000000000000000000000000000007caee97613e6700000')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #9 done')
                    break

                except:

                    print(f'{datetime.now()} | [{acc.address}] - Transaction #9 ERROR')
                    sleep(5)
            while True:
                try:
                    # approve wbtc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #10')
                    make_transaction(
                        6721975, '0xA69506eAbdC11BBdAf2259882A02a91B66E6d7E1', acc, '0x095ea7b3000000000000000000000000981bd5832eab9c8f607940e0e9facbf8c09ee20affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #10 done')
                    break

                except:

                    print(f'{datetime.now()} | [{acc.address}] - Transaction #10 ERROR')
                    sleep(5)
            while True:
                try:
                    # deposit wbtc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #11')
                    make_transaction(
                        6721975, '0x981bD5832EAB9C8F607940E0e9faCBf8C09ee20a', acc, '0xa0712d6800000000000000000000000000000000000000000000000000000000005b8d80')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #11 done')
                    break

                except:

                    print(f'{datetime.now()} | [{acc.address}] - Transaction #11 ERROR')
                    sleep(5)
            while True:
                try:
                    # collateral wbtc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #12')
                    make_transaction(
                        6721975, '0x79e62AAfc1675c9F737Ec4Bb949115bfC8D2E2E6', acc, '0xc299823800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000981bd5832eab9c8f607940e0e9facbf8c09ee20a')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #12 done')
                    break

                except:

                    print(f'{datetime.now()} | [{acc.address}] - Transaction #12 ERROR')
                    sleep(5)
            while True:
                try:
                    # collateral dai
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #13')
                    make_transaction(
                        6721975, '0x79e62AAfc1675c9F737Ec4Bb949115bfC8D2E2E6', acc, '0xc299823800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c337343d1ac9f77b1305261ccd17e3799f088d4b')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #13 done')
                    break

                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #13 ERROR')
                    sleep(5)
            while True:
                try:
                    # collateral usdt
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #14')
                    make_transaction(
                        6721975, '0x79e62AAfc1675c9F737Ec4Bb949115bfC8D2E2E6', acc, '0xc299823800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dacc02a4ff16ea3c1515adbfdceb7b1f448b79c8')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #14 done')
                    break

                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #14 ERROR')
                    sleep(5)
            while True:
                try:
                    # collateral usdc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #15')
                    make_transaction(
                        6721975, '0x79e62AAfc1675c9F737Ec4Bb949115bfC8D2E2E6', acc, '0xc2998238000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000007a9984522bc81b348d66379ed36be5bd6147820e')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #15 done')
                    break

                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #15 ERROR')
                    sleep(5)
            while True:
                try:
                    # borrow wbtc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #16')
                    make_transaction(
                        6721975, '0x981bD5832EAB9C8F607940E0e9faCBf8C09ee20a', acc, '0xc5ebeaec00000000000000000000000000000000000000000000000000000000004c4b40')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #16 done')
                    break

                except:
                    
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #16 ERROR')
                    sleep(5)
            while True:
                try:
                    # borrow dai
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #17')
                    make_transaction(
                        6721975, '0xc337343d1ac9f77b1305261ccd17e3799f088d4b', acc, '0xc5ebeaec00000000000000000000000000000000000000000000006c6b935b8bbd400000')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #17 done')
                    break
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #17 ERROR')
                    sleep(5)
            while True:
                try:
                    # borrow usdt
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #18')
                    make_transaction(
                        6721975, '0xdacc02a4ff16ea3c1515adbfdceb7b1f448b79c8', acc, '0xc5ebeaec0000000000000000000000000000000000000000000000000000000077359400')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #18 done')
                    break
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #18 ERROR')
                    sleep(5)
            while True:
                try:
                    # borrow usdc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #19')
                    make_transaction(
                        6721975, '0x8A1dD36BffF0b17931Cb9914f8d7866b7249FF0e', acc, '0xc5ebeaec0000000000000000000000000000000000000000000000000000000077359400')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #19 done')
                    break
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #19 ERROR')
                    sleep(5)
            while True:
                try:
                    # repay wbtc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #20')
                    make_transaction(
                        6721975, '0x981bD5832EAB9C8F607940E0e9faCBf8C09ee20a', acc, '0x0e752702ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #20 done')
                    break
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #20 ERROR')
                    sleep(5)
            while True:
                try:
                    # repay dai
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #21')
                    make_transaction(
                        6721975, '0xc337343d1ac9f77b1305261ccd17e3799f088d4b', acc, '0x0e752702ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #21 done')
                    break
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #21 ERROR')
                    sleep(5)
            while True:
                try:
                    # repay usdt
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #22')
                    make_transaction(
                        6721975, '0xdacc02a4ff16ea3c1515adbfdceb7b1f448b79c8', acc, '0x0e752702ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #22 done')
                    break
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #22 ERROR')
                    sleep(5)
            while True:
                try:
                    # repay usdc
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #23')
                    make_transaction(
                        6721975, '0x7A9984522bC81B348d66379ed36Be5BD6147820E', acc, '0x0e752702ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #23 done')
                    break
                except:
                    print(f'{datetime.now()} | [{acc.address}] - Transaction #23 ERROR')
                    sleep(5)
            lock.acquire()
            
            
            with open('aurigami.txt', 'a') as f:
                f.write(f'{acc.address}:{acc.privateKey.hex()}\n')
            lock.release()
        except Exception as e:
            print(f'{datetime.now()} | Error: {e}')
            sleep(4)
            continue


for _ in range(2):
    Thread(target=a, args=()).start()

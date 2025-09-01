from bitcoinrpc.authproxy import AuthServiceProxy
import time
from decimal import Decimal

# RPC Connection Details
RPC_USER = "alice"
RPC_PASSWORD = "password"
RPC_PORT = 18443  # Default for regtest
RPC_HOST = "127.0.0.1"

# Connect to Bitcoin Node via RPC
rpc_url = f"http://{RPC_USER}:{RPC_PASSWORD}@{RPC_HOST}:{RPC_PORT}"
rpc_conn = AuthServiceProxy(rpc_url)

# Test connection
try:
    blockchain_info = rpc_conn.getblockchaininfo()
    print("Connected successfully to Bitcoin Node!")
    print(f"Block height: {blockchain_info['blocks']}")
except Exception as e:
    print(f"Error connecting to Bitcoin node: {e}")
    exit()

# Step 1: Check if Wallet Exists and Use It
wallet_name = "testwallet"
existing_wallets = rpc_conn.listwallets()

if wallet_name not in existing_wallets:
    print(f"Wallet '{wallet_name}' not found. Creating and loading it...")
    rpc_conn.createwallet(wallet_name)
    time.sleep(2)
else:
    print(f"Wallet '{wallet_name}' is already loaded.")

# Connect to the wallet RPC
rpc_conn = AuthServiceProxy(f"http://{RPC_USER}:{RPC_PASSWORD}@{RPC_HOST}:{RPC_PORT}/wallet/{wallet_name}")

# Step 2: Generate New Address for Mining Rewards
btc_address = rpc_conn.getnewaddress()
print(f"New address for mining rewards: {btc_address}")

# Step 3: Mine Blocks to Fund Wallet
print("Mining 101 blocks to fund the wallet...")
rpc_conn.generatetoaddress(200, btc_address)
time.sleep(5)

# Step 4: Select Enough UTXOs for Transaction
required_amount = Decimal("100.0")  # BTC to send
selected_utxos = []
total_selected_amount = Decimal("0")

utxos = rpc_conn.listunspent()
if not utxos:
    raise Exception("No UTXOs found! Ensure the wallet has funds by mining blocks.")

# Select UTXOs with 10% buffer for fee estimation
for utxo in utxos:
    selected_utxos.append({
        "txid": utxo["txid"],
        "vout": utxo["vout"]
    })
    total_selected_amount += Decimal(str(utxo["amount"]))
    if total_selected_amount >= required_amount * Decimal("1.1"):
        break

if total_selected_amount < required_amount:
    raise Exception(f"Not enough funds! Available: {total_selected_amount} BTC, Needed: {required_amount} BTC")

print(f"Selected UTXOs with a total of {total_selected_amount} BTC")

# Step 5: Create Initial Transaction Structure
recipient_address = "bcrt1qq2yshcmzdlznnpxx258xswqlmqcxjs4dssfxt2"

# CORRECTED STEP 5: Create OP_RETURN output
op_return_message = "We are all Satoshi!!"
op_return_bytes = op_return_message.encode("utf-8")[:20]  # Strictly limit to 20 bytes after encoding
op_return_data = op_return_bytes.hex()  # Only raw data bytes

outputs = {
    recipient_address: float(required_amount),
    "data": op_return_data  # Let Bitcoin Core add OP_RETURN + push opcode
}

print(f"OP_RETURN raw data: {op_return_data} (20 bytes)")


# Step 6: Fee Calculation with Change Recalculation Loop
fee_rate = 21  # sats/vB
max_attempts = 3

for attempt in range(max_attempts):
    # Create temporary transaction
    raw_tx = rpc_conn.createrawtransaction(selected_utxos, outputs)
    signed_tx = rpc_conn.signrawtransactionwithwallet(raw_tx)
    tx_details = rpc_conn.decoderawtransaction(signed_tx["hex"])
    
    tx_size_vb = tx_details["vsize"]
    total_fee_sats = tx_size_vb * fee_rate
    total_fee_btc = Decimal(total_fee_sats) / Decimal(1e8)
    
    # Calculate required funds with updated fee
    required_total = required_amount + total_fee_btc
    change_amount = total_selected_amount - required_total
    
    if change_amount < 0:
        raise Exception(f"Insufficient funds! Need {required_total:.8f} BTC, have {total_selected_amount:.8f} BTC")
    
    # Update or add change output
    if change_amount > 0:
        if 'change_address' not in locals():
            change_address = rpc_conn.getnewaddress()
        outputs[change_address] = float(change_amount)
    else:
        if change_address in outputs:
            del outputs[change_address]
    
    # Check if we've reached equilibrium
    if attempt > 0 and abs(prev_fee - total_fee_sats) < 10:
        break
        
    prev_fee = total_fee_sats

print(f"Final Transaction Size: {tx_size_vb} vB")
print(f"Final Fee: {total_fee_btc:.8f} BTC ({fee_rate} sats/vB)")

# Step 7: Create and Broadcast Final Transaction
final_raw_tx = rpc_conn.createrawtransaction(selected_utxos, outputs)
final_signed_tx = rpc_conn.signrawtransactionwithwallet(final_raw_tx)

if not final_signed_tx["complete"]:
    raise Exception("Transaction signing failed!")

txid = rpc_conn.sendrawtransaction(final_signed_tx["hex"])

# Step 8: Save Transaction ID
with open("out.txt", "w") as f:
    f.write(txid)

print(f"Transaction Broadcasted! TXID: {txid}")

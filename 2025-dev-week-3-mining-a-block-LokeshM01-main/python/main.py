import os
import json
import hashlib
import time
from struct import pack
from io import BytesIO

mempool_folder = "mempool"
output_file = "out.txt"
target_threshold = bytes.fromhex("0000ffff00000000000000000000000000000000000000000000000000000000")
witness_reserved_value = bytes(32)
max_block_size = 4000000

def hash_twice(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# Load transaction files from the mempool folder
tx_list = []
for filename in os.listdir(mempool_folder):
    if filename.endswith('.json'):
        file_path = os.path.join(mempool_folder, filename)
        try:
            with open(file_path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    tx_list.extend(data)
                else:
                    tx_list.append(data)
        except Exception as e:
            print(f"Skipping {filename}: {str(e)}")

# Select transactions to fit within block weight limits
valid_txs = [tx for tx in tx_list if all(field in tx for field in ('fee', 'weight'))]
valid_txs.sort(key=lambda tx: tx['fee'] / tx['weight'], reverse=True)
selected_txs = []
total_weight = 0
for tx in valid_txs:
    if (total_weight + tx['weight']) <= (max_block_size - 4000):
        selected_txs.append(tx)
        total_weight += tx['weight']

total_fees = sum(tx['fee'] for tx in selected_txs)

# Compute wtxid list
tx_wtxid_list = []
coinbase_stream = BytesIO()
tx_version = pack('<I', 1)
segwit_marker = b'\x00'
segwit_flag = b'\x01'
script_sig = pack('<B', 4) + b'\x00'*4
coinbase_stream.write(tx_version)
coinbase_stream.write(segwit_marker)
coinbase_stream.write(segwit_flag)
coinbase_stream.write(b'\x01')
coinbase_stream.write(bytes(32))
coinbase_stream.write(pack('<I', 0xFFFFFFFF))
coinbase_stream.write(bytes([len(script_sig)]))
coinbase_stream.write(script_sig)
coinbase_stream.write(b'\xFF'*4)
coinbase_stream.write(b'\x02')
coinbase_stream.write(pack('<Q', 5000000000 + total_fees))
coinbase_stream.write(b'\x19')
coinbase_stream.write(bytes.fromhex('76a914000000000000000000000000000000000000000088ac'))
commitment_script = bytes.fromhex('6a24aa21a9ed') + bytes(32)
coinbase_stream.write(b'\x00'*8)
coinbase_stream.write(bytes([len(commitment_script)]))
coinbase_stream.write(commitment_script)
coinbase_stream.write(b'\x01')
coinbase_stream.write(b'\x20')
coinbase_stream.write(witness_reserved_value)
coinbase_stream.write(pack('<I', 0))
coinbase_tx = coinbase_stream.getvalue()
tx_wtxid_list.append(hash_twice(coinbase_tx)[::-1].hex())

for tx in selected_txs:
    tx_wtxid_list.append(hash_twice(bytes.fromhex(tx['hex']))[::-1].hex())

# Compute witness commitment
hash_list = [bytes(32)] + [bytes.fromhex(txid)[::-1] for txid in tx_wtxid_list[1:]] if tx_wtxid_list else []
while len(hash_list) > 1:
    if len(hash_list) % 2:
        hash_list.append(hash_list[-1])
    hash_list = [hash_twice(hash_list[i] + hash_list[i+1]) for i in range(0, len(hash_list), 2)]
witness_root_hash = hash_list[0] if hash_list else bytes(32)
witness_commitment_value = hash_twice(witness_root_hash + witness_reserved_value)

# Recreate coinbase transaction with correct witness commitment
coinbase_stream = BytesIO()
coinbase_stream.write(tx_version)
coinbase_stream.write(segwit_marker)
coinbase_stream.write(segwit_flag)
coinbase_stream.write(b'\x01')
coinbase_stream.write(bytes(32))
coinbase_stream.write(pack('<I', 0xFFFFFFFF))
coinbase_stream.write(bytes([len(script_sig)]))
coinbase_stream.write(script_sig)
coinbase_stream.write(b'\xFF'*4)
coinbase_stream.write(b'\x02')
coinbase_stream.write(pack('<Q', 5000000000 + total_fees))
coinbase_stream.write(b'\x19')
coinbase_stream.write(bytes.fromhex('76a914000000000000000000000000000000000000000088ac'))
commitment_script = bytes.fromhex('6a24aa21a9ed') + witness_commitment_value
coinbase_stream.write(b'\x00'*8)
coinbase_stream.write(bytes([len(commitment_script)]))
coinbase_stream.write(commitment_script)
coinbase_stream.write(b'\x01')
coinbase_stream.write(b'\x20')
coinbase_stream.write(witness_reserved_value)
coinbase_stream.write(pack('<I', 0))
coinbase_tx_final = coinbase_stream.getvalue()
coinbase_wtxid = hash_twice(coinbase_tx_final)[::-1].hex()

# Build merkle root
tx_id_list = [coinbase_wtxid] + [tx['txid'] for tx in selected_txs]
hash_items = [bytes.fromhex(txid)[::-1] for txid in tx_id_list] if tx_id_list else []
while len(hash_items) > 1:
    if len(hash_items) % 2:
        hash_items.append(hash_items[-1])
    hash_items = [hash_twice(hash_items[i] + hash_items[i+1]) for i in range(0, len(hash_items), 2)]
merkle_root_hash = hash_items[0] if hash_items else bytes(32)

# Block mining setup
block_version = pack('<I', 0x20000000)
prev_block_hash = bytes(32)
timestamp_now = pack('<I', int(time.time()))
block_bits = pack('<I', 0x1f00ffff)
block_header = block_version + prev_block_hash + merkle_root_hash + timestamp_now + block_bits
target_value = target_threshold

# Finding a valid nonce
for nonce in range(0, 0xFFFFFFFF):
    full_block_header = block_header + pack('<I', nonce)
    block_hash_attempt = hash_twice(full_block_header)[::-1]
    if block_hash_attempt < target_value:
        mined_block_header = full_block_header
        mined_nonce = nonce
        break
else:
    raise ValueError("Valid nonce not found")

# Save mined block data
with open(output_file, 'w') as f:
    f.write(mined_block_header.hex() + '\n')
    f.write(coinbase_tx_final.hex() + '\n')
    f.write('\n'.join([coinbase_wtxid] + [tx['txid'] for tx in selected_txs]))
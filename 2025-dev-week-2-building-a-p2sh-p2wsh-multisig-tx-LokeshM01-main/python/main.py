import hashlib
import struct
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
import base58

# Helper function to serialize variable-length integers
def serialize_varint(value):
    """Serialize a variable-length integer to bytes."""
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + struct.pack('<H', value)
    elif value <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', value)
    else:
        return b'\xff' + struct.pack('<Q', value)

# Function to create witness program from a redeem script
def create_witness_program(redeem_script):
    """Create the witness program by applying SHA256 to the redeem script."""
    return bytes([0x00, 0x20]) + hashlib.sha256(redeem_script).digest()

# Function to create scriptSig from the witness program
def create_scriptSig(witness_program):
    """Create the scriptSig to push the witness program to the stack."""
    return serialize_varint(len(witness_program)) + witness_program

# Function to derive a P2SH address from the witness program
def derive_p2sh_address(witness_program):
    """Derive the P2SH address from the witness program by performing a RIPEMD160(SHA256) hash."""
    hash160 = hashlib.new('ripemd160', hashlib.sha256(witness_program).digest()).digest()
    return base58.b58encode_check(b'\x05' + hash160).decode()

# Function to create the scriptPubKey for an output address
def create_scriptPubKey(output_address):
    """Create the scriptPubKey for a given output address."""
    decoded = base58.b58decode_check(output_address)
    output_hash160 = decoded[1:]
    return bytes([0xa9, 0x14]) + output_hash160 + bytes([0x87])

# Function to serialize inputs for transaction
def serialize_inputs(tx_inputs):
    """Serialize transaction inputs into a byte stream."""
    serialized_inputs = b''
    for txin in tx_inputs:
        serialized_inputs += txin['prev_txid']
        serialized_inputs += struct.pack('<I', txin['prev_index'])
        serialized_inputs += serialize_varint(len(txin['script_sig'])) + txin['script_sig']
        serialized_inputs += struct.pack('<I', txin['sequence'])
    return serialized_inputs

# Function to serialize outputs for transaction
def serialize_outputs(tx_outputs):
    """Serialize transaction outputs into a byte stream."""
    serialized_outputs = b''
    for txout in tx_outputs:
        serialized_outputs += struct.pack('<Q', txout['value'])
        serialized_outputs += serialize_varint(len(txout['script_pubkey'])) + txout['script_pubkey']
    return serialized_outputs

# Function to create sighash for the transaction
def calculate_sighash(tx_version, tx_inputs, tx_outputs, redeem_script, locktime):
    """Calculate the BIP143 sighash for the transaction."""
    prevouts = hashlib.sha256(hashlib.sha256(b''.join(
        [txin['prev_txid'] + struct.pack('<I', txin['prev_index']) for txin in tx_inputs]
    )).digest()).digest()

    sequences = hashlib.sha256(hashlib.sha256(b''.join(
        struct.pack('<I', txin['sequence']) for txin in tx_inputs
    )).digest()).digest()

    scriptCode = serialize_varint(len(redeem_script)) + redeem_script

    outputs = hashlib.sha256(hashlib.sha256(b''.join(
        [struct.pack('<Q', txout['value']) + serialize_varint(len(txout['script_pubkey'])) + txout['script_pubkey']
        for txout in tx_outputs]
    )).digest()).digest()

    preimage = (
        struct.pack('<I', tx_version) +
        prevouts +
        sequences +
        tx_inputs[0]['prev_txid'] +
        struct.pack('<I', tx_inputs[0]['prev_index']) +
        scriptCode +
        struct.pack('<Q', 100000) +  # UTXO value
        struct.pack('<I', tx_inputs[0]['sequence']) +
        outputs +
        struct.pack('<I', 0) +  # locktime
        struct.pack('<I', 0x01)  # SIGHASH_ALL
    )

    return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()

# Function to generate signatures for a multisig transaction
def generate_signatures(sighash, priv_key_1, priv_key_2):
    """Generate signatures for the multisig transaction."""
    priv1 = SigningKey.from_string(bytes.fromhex(priv_key_1), curve=SECP256k1)
    sig1 = priv1.sign_digest(sighash, sigencode=sigencode_der) + bytes([0x01])

    priv2 = SigningKey.from_string(bytes.fromhex(priv_key_2), curve=SECP256k1)
    sig2 = priv2.sign_digest(sighash, sigencode=sigencode_der) + bytes([0x01])

    return sig1, sig2

# Function to assemble the full transaction, including witness
def assemble_transaction(tx_version, tx_inputs, tx_outputs, witness, locktime):
    """Assemble the full transaction, including witness and inputs/outputs."""
    tx_bytes = bytearray()
    tx_bytes += struct.pack('<I', tx_version)
    tx_bytes += b'\x00\x01'  # SegWit marker and flag

    # Serialize Inputs
    tx_bytes += serialize_varint(len(tx_inputs))
    tx_bytes += serialize_inputs(tx_inputs)

    # Serialize Outputs
    tx_bytes += serialize_varint(len(tx_outputs))
    tx_bytes += serialize_outputs(tx_outputs)

    # Serialize Witness
    tx_bytes += serialize_varint(len(witness))
    for item in witness:
        tx_bytes += serialize_varint(len(item)) + item

    tx_bytes += struct.pack('<I', locktime)  # Locktime

    return tx_bytes

# Function to write the transaction to a file
def write_transaction_to_file(tx_bytes):
    """Write the serialized transaction to a file for debugging purposes."""
    with open('out.txt', 'w') as f:
        f.write(tx_bytes.hex())

# Main code block to execute the transaction creation process
if __name__ == "__main__":
    # Redeem script and its witness program creation
    redeem_script_hex = '5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae'
    redeem_script = bytes.fromhex(redeem_script_hex)
    witness_program = create_witness_program(redeem_script)

    # ScriptSig creation
    script_sig = create_scriptSig(witness_program)

    # P2SH Address derivation
    p2sh_address = derive_p2sh_address(witness_program)
    print(f"Derived P2SH Address: {p2sh_address}")

    # Transaction components (inputs, outputs, etc.)
    tx_version = 2
    tx_inputs = [{
        'prev_txid': bytes.fromhex('0'*64),
        'prev_index': 0,
        'script_sig': script_sig,
        'sequence': 0xffffffff
    }]
    
    output_address = '325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF'
    script_pubkey = create_scriptPubKey(output_address)
    
    tx_outputs = [{
        'value': 100000,  # 0.001 BTC in satoshis
        'script_pubkey': script_pubkey
    }]
    
    # Sighash calculation
    sighash = calculate_sighash(tx_version, tx_inputs, tx_outputs, redeem_script, 0)
    print(f"Sighash: {sighash.hex()}")

    # Generate signatures
    priv_key_1 = '39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf'
    priv_key_2 = '5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d'
    sig1, sig2 = generate_signatures(sighash, priv_key_1, priv_key_2)

    print(f"Signature 1: {sig1.hex()}")
    print(f"Signature 2: {sig2.hex()}")

    # Witness construction
    witness = [
        b'',  # Dummy element for multisig
        sig2,  # Signature for privKey2 (corresponding to pubKey2)
        sig1,  # Signature for privKey1 (corresponding to pubKey1)
        redeem_script
    ]
    
    print(f"Witness stack: {[w.hex() for w in witness]}")

    # Assemble the full transaction
    tx_bytes = assemble_transaction(tx_version, tx_inputs, tx_outputs, witness, 0)

    # Write the transaction to a file
    write_transaction_to_file(tx_bytes)

    # Debugging output for the full serialized transaction
    print(f"Serialized Transaction: {tx_bytes.hex()}")

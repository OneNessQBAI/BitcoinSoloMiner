import requests
import hashlib
import time
import struct
import multiprocessing
import binascii
import random

# Configuration
RPC_USER = "YOUR_UESR_NAME"
RPC_PASSWORD = "YOUR_Pass_Word"
RPC_URL = "http://127.0.0.1:8332"
BITCOIN_ADDRESS = "YOUR_BITCOIN_WALLET_FOR_REWARD"

# Threading and multiprocessing locks for secure handling
nonce_lock = multiprocessing.Lock()
correct_nonce = multiprocessing.Value('i', 0)
correct_hash = multiprocessing.Array('c', b' ' * 64)

def classical_sha256(message):
    """Classical SHA-256 implementation using hashlib."""
    return hashlib.sha256(message).hexdigest()

def get_block_template():
    """Fetch the latest block template from the RPC server."""
    print("Fetching block template...")
    try:
        payload = {
            "method": "getblocktemplate",
            "params": [{"rules": ["segwit"]}],
            "jsonrpc": "2.0",
            "id": 0,
        }
        response = requests.post(RPC_URL, json=payload, auth=(RPC_USER, RPC_PASSWORD))
        response.raise_for_status()
        result = response.json()
        if 'error' in result and result['error'] is not None:
            raise Exception(f"RPC error: {result['error']}")
        print("Block template fetched successfully.")
        return result['result']
    except Exception as e:
        print(f"Error fetching block template: {e}")
        return None

def create_coinbase_transaction(height, coinbase_value):
    """Create a coinbase transaction."""
    print("Creating coinbase transaction...")
    try:
        script_sig = struct.pack("<I", height) + b"OneNess" + b"\0" * 92
        tx_in = b"\0" * 32 + b"\xff" * 4 + struct.pack('<B', len(script_sig)) + script_sig + b"\xff" * 4
        
        script_pubkey = b"\x76\xa9\x14" + hashlib.new('ripemd160', hashlib.sha256(BITCOIN_ADDRESS.encode()).digest()).digest() + b"\x88\xac"
        tx_out = struct.pack('<Q', coinbase_value) + struct.pack('<B', len(script_pubkey)) + script_pubkey
        
        tx = struct.pack('<I', 1) + b'\x01' + tx_in + b'\x01' + tx_out + struct.pack('<I', 0)
        print("Coinbase transaction created.")
        return tx
    except Exception as e:
        print(f"Error creating coinbase transaction: {e}")
        return None

def assemble_block_header(version, prev_block, merkle_root, timestamp, bits, nonce):
    """Assemble the block header."""
    print(f"Assembling block header with nonce {nonce}...")
    try:
        header = struct.pack('<I', version)
        header += binascii.unhexlify(prev_block)[::-1]
        header += binascii.unhexlify(merkle_root)[::-1]
        header += struct.pack('<I', timestamp)
        header += struct.pack('<I', int(bits, 16))
        header += struct.pack('<I', nonce)
        return header
    except Exception as e:
        print(f"Error assembling block header: {e}")
        return None

def calculate_merkle_root(txids):
    """Calculate the Merkle root from transaction IDs."""
    print("Calculating Merkle root...")
    try:
        while len(txids) > 1:
            if len(txids) % 2 != 0:
                txids.append(txids[-1])
            new_txids = []
            for i in range(0, len(txids), 2):
                combined = binascii.unhexlify(txids[i])[::-1] + binascii.unhexlify(txids[i+1])[::-1]
                new_txids.append(hashlib.sha256(hashlib.sha256(combined).digest()).digest()[::-1].hex())
            txids = new_txids
        print("Merkle root calculated.")
        return txids[0]
    except Exception as e:
        print(f"Error calculating Merkle root: {e}")
        return None

def submit_block(block_hex):
    """Submit the mined block to the RPC server."""
    print("Submitting block to the network...")
    try:
        payload = {
            "method": "submitblock",
            "params": [block_hex],
            "jsonrpc": "2.0",
            "id": 0,
        }
        response = requests.post(RPC_URL, json=payload, auth=(RPC_USER, RPC_PASSWORD))
        response.raise_for_status()
        result = response.json()
        if result.get('result') is None:
            print("Block submitted successfully!")
        else:
            print(f"Block submission error: {result.get('result')}")
    except Exception as e:
        print(f"Failed to submit block: {e}")

def search_nonce(version, prev_block, merkle_root, timestamp, bits, start_nonce, end_nonce):
    global correct_nonce, correct_hash
    for nonce in range(start_nonce, end_nonce):
        if correct_nonce.value != 0:
            return
        # Adding randomness to the nonce search
        nonce = random.randint(start_nonce, end_nonce)
        header = assemble_block_header(version, prev_block, merkle_root, timestamp, bits, nonce)
        if header:
            hash_result = classical_sha256(header)

            if int(hash_result, 16) < int(bits, 16):
                with nonce_lock:
                    if correct_nonce.value == 0:
                        correct_nonce.value = nonce
                        correct_hash.value = hash_result.encode()
                        print(f"Nonce found: {nonce}, Hash: {hash_result}")

def mine_block():
    global correct_nonce, correct_hash
    while True:
        block_template = get_block_template()
        if block_template:
            coinbase_tx = create_coinbase_transaction(
                height=block_template['height'], 
                coinbase_value=block_template['coinbasevalue']
            )
            if coinbase_tx:
                coinbase_txid = hashlib.sha256(hashlib.sha256(coinbase_tx).digest()).digest()[::-1].hex()

                txids = [coinbase_txid] + [tx['txid'] for tx in block_template['transactions']]
                merkle_root = calculate_merkle_root(txids)
                timestamp = int(time.time())
                
                # Determine the number of cores
                num_threads = multiprocessing.cpu_count() * 3  # Tripled the number of cores
                nonce_range = 2**32 // num_threads
                processes = []
                
                correct_nonce.value = 0  # Reset nonce
                correct_hash.value = b' ' * 64  # Reset hash
                
                with multiprocessing.Manager():
                    for i in range(num_threads):
                        start_nonce = i * nonce_range
                        end_nonce = start_nonce + nonce_range
                        p = multiprocessing.Process(target=search_nonce, args=(
                            block_template['version'],
                            block_template['previousblockhash'],
                            merkle_root,
                            timestamp,
                            block_template['bits'],
                            start_nonce,
                            end_nonce
                        ))
                        processes.append(p)
                        p.start()

                    for p in processes:
                        p.join()

                if correct_nonce.value != 0:
                    final_header = assemble_block_header(
                        block_template['version'], 
                        block_template['previousblockhash'], 
                        merkle_root, 
                        timestamp, 
                        block_template['bits'], 
                        correct_nonce.value
                    )
                    block = final_header + struct.pack('<I', len(block_template['transactions']) + 1) + coinbase_tx
                    for tx in block_template['transactions']:
                        block += binascii.unhexlify(tx['data'])
                    submit_block(block.hex())
        
        time.sleep(20)  # Wait 20 seconds before fetching a new block template

if __name__ == "__main__":
    mine_block()

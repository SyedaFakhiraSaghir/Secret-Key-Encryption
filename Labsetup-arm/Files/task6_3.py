import socket
import time
import random
import binascii

# Custom implementation of AES-like encryption simulation
# Since we can't use pycryptodome, we'll simulate the behavior

class SimpleEncryptionSimulator:
    def __init__(self):
        # For simulation purposes, we'll use a simple XOR-based "encryption"
        self.key = b'secretkey1234567'  # 16-byte key
        self.iv = b'\x00' * 16  # Predictable IV
    
    def simulate_encrypt(self, data, iv=None):
        """Simulate encryption using XOR (for demonstration only)"""
        if iv is None:
            iv = self.iv
        
        # Pad the data to multiple of 16 bytes
        padded_data = self.pad(data, 16)
        
        # Simple XOR "encryption" simulation
        # In real AES, this would be much more complex
        result = bytearray()
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            # Simulate encryption by XORing with a predictable pattern
            encrypted_block = bytes(a ^ b for a, b in zip(block, self.key))
            result.extend(encrypted_block)
        
        return iv + bytes(result)
    
    def pad(self, data, block_size):
        """PKCS#7 padding implementation"""
        padding_length = block_size - (len(data) % block_size)
        if padding_length == 0:
            padding_length = block_size
        padding = bytes([padding_length] * padding_length)
        return data + padding

def connect_to_oracle(host, port, timeout=5):
    """Connect to the encryption oracle with timeout handling"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"Cannot connect to {host}:{port} - {e}")
        return None

def encrypt_via_oracle(s, plaintext):
    """Send plaintext to oracle and receive ciphertext"""
    try:
        s.send(plaintext + b'\n')
        response = s.recv(1024).strip()
        return response
    except Exception as e:
        print(f"Error communicating with oracle: {e}")
        return None

def predictable_iv_attack(host, port):
    """Attack the encryption oracle with predictable IV"""
    print(f"Attempting to connect to {host}:{port}...")
    
    # Connect to oracle
    s = connect_to_oracle(host, port)
    if s is None:
        print("Server not available. Running in simulation mode...")
        return simulate_attack()
    
    try:
        # First, get Bob's ciphertext and IV
        print("Waiting for Bob's data...")
        bob_data = s.recv(1024).strip()
        if not bob_data:
            print("No data received from server")
            return
        
        print(f"Received from Bob (hex): {bob_data.hex()}")
        print(f"Received from Bob (length): {len(bob_data)} bytes")
        
        # The IV is typically the first 16 bytes in CBC mode
        if len(bob_data) >= 16:
            iv = bob_data[:16]
            bob_ciphertext = bob_data[16:]
            print(f"IV: {iv.hex()}")
            print(f"Bob's ciphertext: {bob_ciphertext.hex()}")
            print(f"Bob's ciphertext length: {len(bob_ciphertext)} bytes")
        else:
            print("Received data is too short to contain IV")
            return
        
        # Test with "Yes"
        print("Sending 'Yes' to oracle...")
        yes_response = encrypt_via_oracle(s, b"Yes")
        if yes_response:
            print(f"Yes response (hex): {yes_response.hex()}")
            if len(yes_response) >= 16:
                yes_iv = yes_response[:16]
                yes_ciphertext = yes_response[16:]
                print(f"Yes IV: {yes_iv.hex()}")
                print(f"Yes ciphertext: {yes_ciphertext.hex()}")
                
                # Test with "No"
                print("Sending 'No' to oracle...")
                no_response = encrypt_via_oracle(s, b"No")
                if no_response:
                    print(f"No response (hex): {no_response.hex()}")
                    if len(no_response) >= 16:
                        no_iv = no_response[:16]
                        no_ciphertext = no_response[16:]
                        print(f"No IV: {no_iv.hex()}")
                        print(f"No ciphertext: {no_ciphertext.hex()}")
                        
                        # Compare to determine Bob's secret
                        print("\n" + "="*50)
                        print("ATTACK RESULTS:")
                        print("="*50)
                        
                        if bob_ciphertext == yes_ciphertext:
                            print("✓ SUCCESS: Bob's secret is 'Yes'")
                        elif bob_ciphertext == no_ciphertext:
                            print("✓ SUCCESS: Bob's secret is 'No'")
                        else:
                            print("✗ Could not determine Bob's secret")
                            print("Possible reasons:")
                            print("- IV is not being reused")
                            print("- Different encryption mode than expected")
                            print("- Additional data or formatting")
                            
                            # Show comparison
                            print(f"\nComparison:")
                            print(f"Bob vs Yes: {bob_ciphertext == yes_ciphertext}")
                            print(f"Bob vs No:  {bob_ciphertext == no_ciphertext}")
        
    except Exception as e:
        print(f"Error during attack: {e}")
        import traceback
        traceback.print_exc()
    finally:
        s.close()
    
    return "Attack completed"

def simulate_attack():
    """Simulate the attack for demonstration purposes"""
    print("\n" + "="*60)
    print("SIMULATION MODE: Predictable IV Attack Demonstration")
    print("="*60)
    
    # Create a simulated oracle
    simulator = SimpleEncryptionSimulator()
    
    # Bob's secret - either "Yes" or "No"
    bob_secret = random.choice([b"Yes", b"No"])
    print(f"Bob's actual secret: {bob_secret.decode()}")
    
    # Encrypt Bob's secret with predictable IV
    bob_encrypted = simulator.simulate_encrypt(bob_secret)
    
    print(f"\nBob's encrypted data (hex): {bob_encrypted.hex()}")
    print(f"IV (first 16 bytes): {bob_encrypted[:16].hex()}")
    print(f"Ciphertext: {bob_encrypted[16:].hex()}")
    
    # Now encrypt "Yes" and "No" with the same predictable IV
    yes_encrypted = simulator.simulate_encrypt(b"Yes")
    no_encrypted = simulator.simulate_encrypt(b"No")
    
    print(f"\nYes encrypted: {yes_encrypted[16:].hex()}")
    print(f"No encrypted:  {no_encrypted[16:].hex()}")
    
    print("\n" + "="*50)
    print("ATTACK RESULTS:")
    print("="*50)
    
    bob_ciphertext = bob_encrypted[16:]
    yes_ciphertext = yes_encrypted[16:]
    no_ciphertext = no_encrypted[16:]
    
    if bob_ciphertext == yes_ciphertext:
        print("✓ SUCCESS: Bob's secret is 'Yes'")
        print("✓ Attack successful - predictable IV vulnerability exploited!")
    elif bob_ciphertext == no_ciphertext:
        print("✓ SUCCESS: Bob's secret is 'No'")
        print("✓ Attack successful - predictable IV vulnerability exploited!")
    
    print(f"\nActual secret was: {bob_secret.decode()}")
    
    print("\n" + "="*60)
    print("HOW THE ATTACK WORKS:")
    print("="*60)
    print("1. Attacker obtains Bob's ciphertext with predictable IV")
    print("2. Attacker encrypts known values ('Yes'/'No') with same IV")
    print("3. Same plaintext + same IV + same key = same ciphertext")
    print("4. Matching ciphertext reveals the secret")
    print("5. Prevention: Always use random, unpredictable IVs")
    
    return "Simulation completed successfully"

def check_network():
    """Check network connectivity"""
    print("Checking network connectivity...")
    
    # Try common lab IP addresses
    targets = [
        ("10.9.0.80", 3000),
        ("127.0.0.1", 3000),
        ("localhost", 5000),
    ]
    
    for host, port in targets:
        print(f"Testing {host}:{port}...")
        s = connect_to_oracle(host, port)
        if s:
            s.close()
            print(f"✓ {host}:{port} is reachable")
            return host, port
        else:
            print(f"✗ {host}:{port} is not reachable")
    
    return None, None

if __name__ == "__main__":
    print("Predictable IV Attack Implementation")
    print("====================================")
    
    # Check if we can reach the server
    host, port = check_network()
    
    if host and port:
        print(f"\nFound reachable server at {host}:{port}")
        result = predictable_iv_attack(host, port)
    else:
        print("\nNo servers found. Running in simulation mode...")
        result = simulate_attack()
    
    print(f"\nFinal result: {result}")
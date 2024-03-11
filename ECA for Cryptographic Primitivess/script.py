from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa, ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hmac
import os
import time
import statistics
import sys

# Useful variables
file_path = "alice.txt"

# Task 1 - Implementations for RSA, DSA, and ECDSA cryptographic algorithms.

# Generating RSA keys with a specified key size
# This function was inspired by cryptography library documentation, part "Generation" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
def generate_rsa_keys(key_size=3072): # Alter for TASK 5
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# Signing a file using RSA algorithm
# This function was inspired by cryptography library documentation, part "Signing" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
def rsa_sign(file_path, private_key, hash_alg=hashes.SHA3_256):
    digest = hashes.Hash(hash_alg())
    # Task 3 - taking files as input and reading it in chunks to ensure reading of files larger than my RAM.
    # Re-used this function from my previous homework assingments
    with open(file_path, "rb") as file:
        for chunk in file:
            digest.update(chunk)
    data_hash = digest.finalize()
    signature = private_key.sign(
        data_hash,
        padding.PSS(
            mgf=padding.MGF1(hash_alg()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hash_alg()  
    )
    return signature

# Verifying a RSA signature
# This function was inspired by cryptography library documentation, part "Verification" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
def rsa_verify(signature, file_path, public_key, hash_alg=hashes.SHA3_256):
    digest = hashes.Hash(hash_alg())
    with open(file_path, "rb") as file:
        for chunk in file:
            digest.update(chunk)
    data_hash = digest.finalize()
    try:
        public_key.verify(
            signature,
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hash_alg()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_alg()
        )
        # Ensuring the signature is valid
        return True
    except InvalidSignature:
        return False

# Generating DSA keys with a specified key size
# This function was inspired by cryptography library documentation, part "Generation" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dsa/)
def generate_dsa_keys(key_size=3072): # Alter for TASK 5
    private_key = dsa.generate_private_key(key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# Signing a file using DSA algorithm
# This function was inspired by cryptography library documentation, part "Signing" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dsa/)
def dsa_sign(file_path, private_key, hash_alg=hashes.SHA3_256):
    digest = hashes.Hash(hash_alg())
    with open(file_path, "rb") as file:
        for chunk in file:
            digest.update(chunk)
    data_hash = digest.finalize()
    signature = private_key.sign(data_hash, hash_alg())
    return signature

# Verifying a RSA signature
# This function was inspired by cryptography library documentation, part "Verification" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dsa/)
def dsa_verify(signature, file_path, public_key, hash_alg=hashes.SHA3_256):
    digest = hashes.Hash(hash_alg())
    with open(file_path, "rb") as file:
        for chunk in file:
            digest.update(chunk)
    data_hash = digest.finalize()
    try:
        public_key.verify(signature, data_hash, hash_alg())
        # Ensuring the signature is valid
        return True
    except InvalidSignature:
        return False


# Generating ECDSA keys with a specified key size
# This function was inspired by cryptography library documentation, part "Generation" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/)
def generate_ecdsa_keys(curve=ec.SECP256R1()): # Alter for TASK 5
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key

# Signing a file using ECDSA algorithm
# This function was inspired by cryptography library documentation, part "Signing" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/)
def ecdsa_sign(file_path, private_key, hash_alg=hashes.SHA3_256):
    digest = hashes.Hash(hash_alg())
    with open(file_path, "rb") as file:
        for chunk in file:
            digest.update(chunk)
    data_hash = digest.finalize()

    return private_key.sign(data_hash, ec.ECDSA(hash_alg()))

# Verifying a RSA signature
# This function was inspired by cryptography library documentation, part "Verification" (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dsa/)
def ecdsa_verify(signature, file_path, public_key, hash_alg=hashes.SHA3_256):
    digest = hashes.Hash(hash_alg())
    with open(file_path, "rb") as file:
        for chunk in file:
            digest.update(chunk)
    data_hash = digest.finalize()
    try:
        public_key.verify(signature, data_hash, ec.ECDSA(hash_alg()))
        # Ensuring the signature is valid
        return True
    except InvalidSignature:
        return False

# TASK 2: Implementing HMAC with SHA2 and SHA3

# Generating a nonce for HMAC to use as a key
def hmac_generate(key_size=16):
    return os.urandom(key_size)

# Computing a tag for the given file to ensure its integrity and authenticity.
# There is a difference, we are not directly signing the file like with the other primitives.
# This function was inspired by cryptography library documentation (https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/)
def hmac_sha2(file_path, key, hash_alg=hashes.SHA256):
    h = hmac.HMAC(key, hash_alg())
    with open(file_path, "rb") as file:
        for chunk in file:
            h.update(chunk)
    return h.finalize()

# Same function, just using SHA3-256
def hmac_sha3(file_path, key, hash_alg=hashes.SHA3_256):
    h = hmac.HMAC(key, hash_alg())
    with open(file_path, "rb") as file:
        for chunk in file:
            h.update(chunk)
    return h.finalize()

# Recomputing the tag to ensure its correct.
def hmac_verify_tag(key, file_path, expected_tag, hash_algorithm):
    h = hmac.HMAC(key, hash_algorithm())
    with open(file_path, "rb") as file:
        for chunk in file:
            h.update(chunk)
    try:
        h.verify(expected_tag)
        return True
    except InvalidSignature:
        return False

# TASK 4: Performing an efficiency comparison analysis

# RSA usage
rsa_private_key, rsa_public_key = generate_rsa_keys()
rsa_signature = rsa_sign(file_path, rsa_private_key)

# DSA usage
dsa_private_key, dsa_public_key = generate_dsa_keys()
dsa_signature = dsa_sign(file_path, dsa_private_key)

# ECDSA usage
ecdsa_private_key, ecdsa_public_key = generate_ecdsa_keys()
ecdsa_signature = ecdsa_sign(file_path, ecdsa_private_key)

# HMAC-SHA2 usage
hmac_sha2_key = hmac_generate()
hmac_sha2_tag = hmac_sha2(file_path, hmac_sha2_key)

# HMAC-SHA3 usage
hmac_sha3_key = hmac_generate()
hmac_sha3_tag = hmac_sha3(file_path, hmac_sha3_key)

# Function for time measurement inspired by this article (https://pythonhow.com/how/measure-elapsed-time-in-python/)
def measure_time(func, *args, **kwargs):
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    time_taken = end_time - start_time
    return time_taken, result

# Function that measures average time for 100 repetitions
def measure_time_avg(func, repetitions=100, *args, **kwargs):
    total_time = 0
    for _ in range(repetitions):
        time_taken, _ = measure_time(func, *args, **kwargs)
        total_time += time_taken
    average_time = total_time / repetitions
    return average_time

# Function for signature generation measurement.
def measure_signature_generation(func, file_path, private_key, repetitions=100):
    # Measuring the average generation time
    average_gen_time = measure_time_avg(
        func, repetitions, file_path, private_key)
    # Getting a signature for verification (using the last run)
    _, signature = measure_time(func, file_path, private_key)
    return average_gen_time, signature

# Function for signature verification measurement.
def measure_signature_verification(func, public_key, signature, file_path, repetitions=100):
    average_ver_time = measure_time_avg(
        func, repetitions, signature, file_path, public_key)
    return average_ver_time

# Special function for HMAC tag generation.
def measure_hmac_generation(hmac_func, file_path, key, repetitions=100):
    total_gen_time = 0
    for _ in range(repetitions):
        gen_time, tag = measure_time(hmac_func, file_path, key)
        total_gen_time += gen_time
    average_gen_time = total_gen_time / repetitions
    return average_gen_time, tag

# Special function for HMAC tag verification
def measure_hmac_verification_avg(hmac_func, file_path, original_tag, key, repetitions=100):
    total_ver_time = 0
    for _ in range(repetitions):
        start_time = time.perf_counter()
        regenerated_tag = hmac_func(file_path, key)
        _ = regenerated_tag == original_tag  # Verification step
        end_time = time.perf_counter()
        ver_time = end_time - start_time
        total_ver_time += ver_time
    average_ver_time = total_ver_time / repetitions
    return average_ver_time


# Here we have average time results for key generation

rsa_key_gen_time = measure_time_avg(generate_rsa_keys)
dsa_key_gen_time = measure_time_avg(generate_dsa_keys)
ecdsa_key_gen_time = measure_time_avg(generate_ecdsa_keys)
hmac_sha2_key_gen_time = measure_time_avg(hmac_generate)
hmac_sha3_key_gen_time = measure_time_avg(hmac_generate)

print("---------KEY GENERATION---------")
print("RSA (AVG on 100 runs): ", rsa_key_gen_time, "seconds")
print("DSA (AVG on 100 runs): ", dsa_key_gen_time, "seconds")
print("ECDSA (AVG on 100 runs): ", ecdsa_key_gen_time, "seconds")
print("HMAC-SHA2 (AVG on 100 runs): ", hmac_sha2_key_gen_time, "seconds")
print("HMAC-SHA3 (AVG on 100 runs): ", hmac_sha3_key_gen_time, "seconds")

# Here we have average time results for signature and tag generation

rsa_sign_time, rsa_signature = measure_signature_generation(
    rsa_sign, file_path, rsa_private_key)
dsa_sign_time, dsa_signature = measure_signature_generation(
    dsa_sign, file_path, dsa_private_key)
ecdsa_sign_time, ecdsa_signature = measure_signature_generation(
    ecdsa_sign, file_path, ecdsa_private_key)
hmac_sha2_sign_time, hmac_sha2_tag = measure_hmac_generation(
    hmac_sha2, file_path, hmac_sha2_key)
hmac_sha3_sign_time, hmac_sha3_tag = measure_hmac_generation(
    hmac_sha3, file_path, hmac_sha3_key)

print("---------SIGNATURE GENERATION---------")
print("RSA (AVG on 100 runs):", rsa_sign_time, "seconds")
print("DSA (AVG on 100 runs):", dsa_sign_time, "seconds")
print("ECDSA (AVG on 100 runs):", ecdsa_sign_time, "seconds")
print("HMAC-SHA2 (AVG on 100 runs):", hmac_sha2_sign_time, "seconds")
print("HMAC-SHA3 (AVG on 100 runs):", hmac_sha3_sign_time, "seconds")

# And here we have average time results for signature or tag verification

rsa_verify_time = measure_signature_verification(
    rsa_verify, rsa_public_key, rsa_signature, file_path)
dsa_verify_time = measure_signature_verification(
    dsa_verify, dsa_public_key, dsa_signature, file_path)
ecdsa_verify_time = measure_signature_verification(
    ecdsa_verify, ecdsa_public_key, ecdsa_signature, file_path)
hmac_sha2_verify_time = measure_hmac_verification_avg(
    hmac_sha2, file_path, hmac_sha2_tag, hmac_sha2_key)
hmac_sha3_verify_time = measure_hmac_verification_avg(
    hmac_sha3, file_path, hmac_sha3_tag, hmac_sha3_key)

print("---------SIGNATURE VERIFICATION---------")
print("RSA (AVG on 100 runs):", rsa_verify_time, "seconds")
print("DSA (AVG on 100 runs):", dsa_verify_time, "seconds")
print("ECDSA (AVG on 100 runs):", ecdsa_verify_time, "seconds")
print("HMAC-SHA2 (AVG on 100 runs):", hmac_sha2_verify_time, "seconds")
print("HMAC-SHA3 (AVG on 100 runs):", hmac_sha3_verify_time, "seconds")

sys.exit()
# TASK 5: Different private key sizes and STD

# Define key sizes for RSA and DSA and curves for ECDSA
rsa_key_sizes = [2048, 3072, 4096]
dsa_key_sizes = [2048, 3072]  # DSA has limitations on key size
ecdsa_curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]  # Different curves for ECDSA

def measure_std(func, params, file_path, repetitions=100):
    # List to store execution times for each key size or curve
    times = []
    # Iterating over each key size or curve 
    for param in params:
        # Handling RSA, DSA, ECDSA key generation
        if func.__name__ in ['generate_rsa_keys', 'rsa_sign', 'rsa_verify']:
            private_key, public_key = generate_rsa_keys(param)
        elif func.__name__ in ['generate_dsa_keys', 'dsa_sign', 'dsa_verify']:
            private_key, public_key = generate_dsa_keys(param)
        elif func.__name__ in ['generate_ecdsa_keys', 'ecdsa_sign', 'ecdsa_verify']:
            private_key, public_key = generate_ecdsa_keys(param)
        # Initializing total time for the current key size or curve
        total_time = 0
        # Repeating the operation to get an average
        for _ in range(repetitions):
            # For signature generation, measure time of the sign function
            if 'sign' in func.__name__:
                time_taken, _ = measure_time(func, file_path, private_key)
            # For signature verification, first sign and then measure verification time
            elif 'verify' in func.__name__:
                # Signature generation for verification
               if func.__name__ in ['rsa_verify', 'dsa_verify', 'ecdsa_verify']:
                    signature_func = globals()[func.__name__.replace('_verify', '_sign')]
                    signature = signature_func(file_path, private_key)
                    time_taken, _ = measure_time(func, signature, file_path, public_key)
            # For key generation, measure the time of key generation function
            else:  # Key generation
                time_taken, _ = measure_time(func, param)
            # Accumulating the time taken for each repetition
            total_time += time_taken
        # Calculating the average time for the current key size or curve
        average_time = total_time / repetitions
        # Appending the average time to the list
        times.append(average_time)
    # Calculating the standard deviation of the recorded times
    std_dev = statistics.stdev(times)
    # Returning the calculated standard deviation
    return std_dev




std_rsa_key_gen = measure_std(generate_rsa_keys, rsa_key_sizes, file_path)
print("Standard Deviation for RSA Key Generation: " + std_rsa_key_gen + " seconds")
std_rsa_sig_gen = measure_std(rsa_sign, rsa_key_sizes, file_path)
print("Standard Deviation for RSA Signature Generation: " + std_rsa_sig_gen + " seconds")
std_rsa_sig_ver = measure_std(rsa_verify, rsa_key_sizes, file_path)
print("Standard Deviation for RSA Signature Verification: " + std_rsa_sig_ver + " seconds")
std_dsa_key_gen = measure_std(generate_dsa_keys, dsa_key_sizes, file_path)
print("Standard Deviation for DSA Key Generation: " + std_dsa_key_gen + " seconds")
std_dsa_sig_gen = measure_std(dsa_sign, dsa_key_sizes, file_path)
print("Standard Deviation for DSA Signature Generation: " + std_dsa_sig_gen + " seconds")
std_dsa_sig_ver = measure_std(dsa_verify, dsa_key_sizes, file_path)
print("Standard Deviation for DSA Signature Verification: " + std_dsa_sig_ver + " seconds")
std_ecdsa_key_gen = measure_std(generate_ecdsa_keys, ecdsa_curves, file_path)
print("Standard Deviation for ECDSA Key Generation: " + std_ecdsa_key_gen + " seconds")
std_ecdsa_sig_gen = measure_std(ecdsa_sign, ecdsa_curves, file_path)
print("Standard Deviation for ECDSA Signature Generation: " + std_ecdsa_sig_gen + " seconds")
std_ecdsa_sig_ver = measure_std(ecdsa_verify, ecdsa_curves, file_path)
print("Standard Deviation for ECDSA Signature Verification: " + std_ecdsa_sig_ver + " seconds")


# Task 6: For this task, see the analysis.pdf file.
# Here, there is a commented out code for generation of 100mb file "big_alice.txt" used later for this task

# def generate_large_file(file_path, file_size_mb):
#     pattern = "The rabbit-hole went straight on like a tunnel for some way, and then dipped suddenly down, so suddenly that Alice had not a moment to think about stopping herself before she found herself falling down a very deep well.\n"
#     pattern_size = len(pattern.encode('utf-8'))
#     total_size = file_size_mb * 1024 * 1024  # Converting MB to bytes

#     with open(file_path, 'w') as file:
#         for _ in range(total_size // pattern_size):
#             file.write(pattern)

#
# file_path = 'big_alice.txt'  # Update this path as needed
# generate_large_file(file_path, 100)
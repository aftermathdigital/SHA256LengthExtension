from pysha256 import SHA256, _pad
import random, string

PRE_SHARED_KEY = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))

def server_generate_sig(message):
    ### Use the pre-shared key to generate a message
    plaintext = (PRE_SHARED_KEY + message).encode('utf-8')
    hash_algo = SHA256()
    hash_algo.update(plaintext)
    signature = hash_algo.hexdigest()
    print(f"[Server] Message signature is: {signature}\n")
    return signature

### START NETWORK TRANSMISSION
### This message, along with the signature are sent over the network
### Note that the pre-shared key does NOT appear inside of this block
### meaning the observer/attacker did NOT know or use the pre-shared-key
def manipulate_sig(message, signature, psk_len):
    ### Break the signature up into register sized chunks
    HASH_LEN = 32 * 2 #2 hex chars = 1 byte
    REG_SIZE = 4 * 2 #2 hex chars = 1 byte

    registers = []
    for i in range(0, HASH_LEN, REG_SIZE):
        hex_string = signature[i : i + REG_SIZE]
        registers.append(int(hex_string, 16))

    print("[Attacker] Got register values:")
    print("\t" + ",".join([hex(x) for x in registers]))

    ### We have the internal register state.
    ### One more step is to calculate and manually pre-pend the padding to our message

    padding = _pad(len(message) + psk_len)

    ### Done, now we can add arbitrary text to our message, re-hash, and forward it
    ### on to the server.
    attacker_message = ", they also have UPDATE, DELETE, and GODMODE"
    malicious_hasher = SHA256()

    ### Replace the internal register state
    malicious_hasher._h = registers
    malicious_hasher._counter = psk_len + len(message) + len(padding)

    ### Pick-up where the hasher left-off
    malicious_hasher.update(attacker_message.encode('utf-8'))

    ### Replace the original message with ours, and update the signature
    attacker_message = message.encode('utf-8') + padding + attacker_message.encode('utf-8')
    signature = malicious_hasher.hexdigest()

    return attacker_message, signature

### END NETWORK TRANSMISSION
### At this point the message + signature has reached the destination
### so we're allowed to use the pre-shared-key again. The server simply
### Checks that sha256(PSK + Message) matches the signature. If it does,
### It accepts the signature, because it believes it is protected by the
### PSK.
def submit_to_server(message, sig):
    hashing_algo = SHA256()
    hashing_algo.update(PRE_SHARED_KEY.encode("utf-8") + message)
    calculated_signature = hashing_algo.hexdigest()
    return (sig == calculated_signature)


MESSAGE = "This user has the following powers: VIEW, CREATE"
SIG = server_generate_sig(MESSAGE)

forged = False
psk_len = 0
for psk_len in range(0, 32):
    attacker_message, forged_sig = manipulate_sig(MESSAGE, SIG, psk_len)
    print(f"[Attacker] Submitting signature to server with a {psk_len} byte PSK: {forged_sig}")
    forged = submit_to_server(attacker_message, forged_sig)
    if forged:
        print(f"\n[Attacker] Forged the signature. The PSK was {psk_len} bytes long")
        break
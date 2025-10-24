import hashlib
import hmac
import argparse

# Stolen from impacket. Thank you all for your wonderful contributions to the community.
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    import logging as LOG
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    sessionKey = cipher.encrypt(exportedSessionKey)
    return sessionKey

###

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u", "--user", required=True, help="User name")
parser.add_argument("-d", "--domain", required=True, help="Domain name")
parser.add_argument("-p", "--password", help="Password of User (provide either this or NTLM hash)")
parser.add_argument("-nh", "--ntlmhash", help="NTLM Hash of the password (provide either this or password)")
parser.add_argument("-n", "--ntproofstr", required=True, help="NTProofStr. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-k", "--key", required=True, help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

args = parser.parse_args()

if not args.password and not args.ntlmhash:
    parser.error("You must provide either the password or the NTLM hash.")

if args.password and args.ntlmhash:
    parser.error("You can only provide one of either the password or the NTLM hash, not both.")

# Upper Case User and Domain
user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')

# Use provided NTLM hash directly or create it from the password
if args.ntlmhash:
    password = bytes.fromhex(args.ntlmhash)
else:
    passw = args.password.encode('utf-16le')
    hash1 = hashlib.new('md4', passw)
    password = hash1.digest()

# Calculate the ResponseNTKey
h = hmac.new(password, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

# Use NTProofSTR and ResponseNTKey to calculate Key Exchange Key
NTproofStr = bytes.fromhex(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

# Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))

if args.verbose:
    print("USER WORK: " + user.decode('utf-16le') + domain.decode('utf-16le'))
    print("PASS HASH: " + password.hex())
    print("RESP NT:   " + respNTKey.hex())
    print("NT PROOF:  " + NTproofStr.hex())
    print("KeyExKey:  " + KeyExchKey.hex())
print("Random SK: " + RsessKey.hex())

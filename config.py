# responder-brute configuration file

# Path to Responder.db
RESPONDERDB = '../Responder.db'

# Current hash file
CURRENTHASHFILE = 'current.txt'

# Poll for new hashes every N seconds
POLLTIME = 5

# Use 'john' for John The Ripper or 'hashcat' for Hashcat.
MODE = 'john'

if MODE == 'john':
    # Command to run. Use "{hashtype}" without quotes where the hash type should be supplied
    # and {hash} where the hash file should be supplied
    COMMAND = 'john --format={hashtype} --wordlist=dictionary.dic {hash}'

    # Hash type format for john
    HASHTYPE_NTLMv1 = 'netntlm'
    HASHTYPE_NTLMv2 = 'netntlmv2'

    # Command to run after COMMAND execution. Not needed for hashcat.
    COMMAND_POST = 'john --show {}'

else:
    # Command to run. Use "{}" without quotes where the hash file should be supplied
    COMMAND = 'hashcat -m {hashtype} -a 0 {hash} dictionary.dic'

    # Hash type format for hashcat
    HASHTYPE_NTLMv1 = '5500'
    HASHTYPE_NTLMv2 = '5600'

    # Command to run after COMMAND execution. Not needed for hashcat.
    COMMAND_POST = None

# Timeout in seconds after which the COMMAND would be terminated
TIMEOUT = 10*60

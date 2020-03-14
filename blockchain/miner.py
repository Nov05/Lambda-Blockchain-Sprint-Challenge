import hashlib
import requests
import sys
from timeit import default_timer as timer


print('Constructing hash dictionary...')
hash_dict = {}
for i in range(16**6):
    key = hashlib.sha256(str(i).encode()).hexdigest()[:6]
    hash_dict[key] = i


def proof_of_work(last_proof):
    """
    Multi-Ouroboros of Work Algorithm
    - Find a number p' such that the last six digits of hash(p) are equal
    to the first six digits of hash(p')
    - IE:  last_hash: ...AE9123456, new hash 123456888...
    - p is the previous proof, and p' is the new proof
    - Use the same method to generate SHA-256 hashes as the examples in class
    """

    start = timer()

    last_hash = hashlib.sha256(str(last_proof).encode()).hexdigest()
    print(f'Last proof: {last_proof}')
    print(f'{last_hash}')
    print("Searching for next proof")

    #  TODO: Your code here
    # check dictionary first, if proof not found, 
    # calculate it and save it to the dictionary
    try:
        proof = hash_dict[last_hash[-6:]]
        print('Find a proof in the hash dictionary')
    except:
        proof = 0
        while not valid_proof(last_hash, str(proof)):
            proof += increment
        hash_dict[last_hash[-6:]] = proof

    print("Proof " + str(proof) + " found in " + str(timer() - start) + " seconds")
    return proof

'''
(base) PS D:\github\Lambda-Blockchain-Sprint-Challenge\blockchain> python miner.py https://lambda-coin-test-1.herokuapp.com/api
ID is XXX
Last proof: 10997720
893bb42179ef29fc850dadcb752cf0cbeaa17dc755550c310f59081e96b4e382
Searching for next proof
Proof 66779165 found in 96.5416858 seconds
Total coins mined: 1
Last proof: 66779165
b4e3821b8a221550ed46e3ab523e1b5e9fde151aa823dbc87956f32e01668251
Searching for next proof
'''


def valid_proof(last_hash, proof):
    """
    Validates the Proof:  Multi-ouroborus:  Do the last six characters of
    the hash of the last proof match the first six characters of the hash
    of the new proof?

    IE:  last_hash: ...AE9123456, new hash 123456E88...
    """

    # TODO: Your code here!
    new_hash = hashlib.sha256(proof.encode()).hexdigest()
    return last_hash[-6:] == new_hash[:6]


if __name__ == '__main__':
    # What node are we interacting with?
    if len(sys.argv) > 1:
        node = sys.argv[1]
    else:
        node = "https://lambda-coin.herokuapp.com/api"

    coins_mined = 0

    # Load or create ID
    f = open("my_id.txt", "r")
    id = f.read()
    print("ID is", id)
    f.close()

    if id == 'NONAME\n':
        print("ERROR: You must change your name in `my_id.txt`!")
        exit()

    # Run forever until interrupted
    while True:
        # Get the last proof from the server
        r = requests.get(url=node + "/last_proof")
        data = r.json()
        new_proof = proof_of_work(data.get('proof'))

        post_data = {"proof": new_proof,
                     "id": id}

        r = requests.post(url=node + "/mine", json=post_data)
        data = r.json()
        if data.get('message') == 'New Block Forged':
            coins_mined += 1
            print("Total coins mined: " + str(coins_mined))
        else:
            print(data.get('message'))

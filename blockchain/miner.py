import hashlib
from timeit import default_timer as timer
import requests
import sys
import json


print('Constructing hash dictionary. It might take a few minutes...')
hash_dict = {}
for i in range(16**6):
    key = hashlib.sha256(str(i).encode()).hexdigest()[:5]
    hash_dict[key] = i

# with open('/content/hash_dict.json', 'r') as f:
#     hash_dict = json.load(f)


def proof_of_work(last_proof):
    """
    Multi-Ouroboros of Work Algorithm
    - Find a number p' such that the last 5 digits of hash(p) are equal
    to the first six digits of hash(p')
    - IE: last_hash: ...AE912345, new hash 12345B88...
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
        proof = hash_dict[last_hash[-5:]]
        print('Find a proof in the hash dictionary')
    except:
        proof = 0
        while not valid_proof(last_hash, str(proof)):
            proof += 1
        hash_dict[last_hash[-5:]] = proof

    print("Proof " + str(proof) + " found in " + str(timer() - start) + " seconds")
    return proof


def valid_proof(last_hash, proof):
    """
    Validates the Proof:  Multi-ouroborus:  Do the last six characters of
    the hash of the last proof match the first 5 characters of the hash
    of the new proof?
    IE: last_hash: ...AE912346, new hash 12345E88...
    """
    # TODO: Your code here!
    new_hash = hashlib.sha256(proof.encode()).hexdigest()
    return last_hash[-5:] == new_hash[:5]


if __name__ == '__main__':
    # What node are we interacting with?
    node = "https://lambda-coin.herokuapp.com/api"
    if len(sys.argv) > 1:
        node = sys.argv[1]
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
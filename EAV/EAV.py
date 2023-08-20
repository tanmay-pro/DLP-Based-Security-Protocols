import os
import sys
PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__), 
                  os.pardir)
)
sys.path.append(PROJECT_ROOT)

from PRG.PRG import PRG

class Eavesdrop:
    def __init__(self, security_parameter: int, key: int, expansion_factor: int,
                 generator: int, prime_field: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param key: k, uniformly sampled key
        :type key: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        self.security_parameter = security_parameter
        self.key = key
        self.expansion_factor = expansion_factor
        self.generator = generator
        self.prime_field = prime_field

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        """
        # expand key to length l(n)
        key = PRG(self.security_parameter, self.generator, self.prime_field, self.expansion_factor).generate(self.key)
        # XOR message with key
        # find length of message bit string
        message_length = len(message)
        message = int(message, 2)
        key = int(key, 2)
        cipher = message ^ key
        # convert to binary string
        cipher = bin(cipher)[2:]
        return cipher



    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        # expand key to length l(n)
        key = PRG(self.security_parameter, self.generator, self.prime_field, self.expansion_factor).generate(self.key)
        # XOR cipher with key
        message = cipher ^ key
        return message
        

if __name__ == "__main__":
    # map input to appropriate types message should be of type str
    security_parameter,key,expansion_factor,generator,prime_field,message =  map(str, input().split(","))
    # convert everything else except message to int
    security_parameter = int(security_parameter)
    key = int(key)
    expansion_factor = int(expansion_factor)
    generator = int(generator)
    prime_field = int(prime_field)
    eav = Eavesdrop(security_parameter,key,expansion_factor,generator,prime_field)
    cipher = eav.enc(message)
    print(cipher)
import os
import sys
PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__), 
                  os.pardir)
)
sys.path.append(PROJECT_ROOT)

from PRG.PRG import DLP
from PRG.PRG import PRG

class PRF:
    def __init__(self, security_parameter: int, generator: int,
                prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.key = key

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        key = self.key
        # traverse through each bit of x
        # convert x to binary string of length security_parameter
        l=x
        x = bin(x)[2:].zfill(self.security_parameter)
        binary = bin(l)[2:]
        if(len(binary) < self.security_parameter):
            binary = '0'*(self.security_parameter - len(binary)) + binary

        for i in range(self.security_parameter):
            # if bit is 1, multiply key by generator
            # Calculate the discrete logarithm problem
            y = PRG(self.security_parameter, self.generator, self.prime_field, 2*self.security_parameter).generate(key)
            # print("y = ", y)
            if x[i] == '1':
                # take right half of y
                key = int(y[self.security_parameter:], 2)
                # print("key = ", key)
            else:
                # take left half of y
                key = int(y[:self.security_parameter], 2)
                # print("key = ", key)
        return key
    
if __name__ == "__main__":
    # take input for security parameter, prime field, generator , key and seed all separated by commans
    security_parameter, prime_field, generator, key, seed = map(int, input().split(","))
    # create an instance of PRF
    prf = PRF(security_parameter, generator, prime_field, key)
    val = prf.evaluate(seed)
    print("PRF({}) = {}".format(seed, val))
    # evaluate the PRF at seed
    

print(PRF(8,36,191,150).evaluate(190))

                           

import os
import sys
PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__), 
                  os.pardir)
)
sys.path.append(PROJECT_ROOT)

from PRF.PRF import PRF

class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.k1 = keys[0]
        self.k2 = keys[1]

    def basic_CBC_MAC(self, message: str, key: int) -> str:
        n = self.security_parameter
        initial_tag = bin(0)[2:].zfill(n)
        num_blocks = len(message)//n
        curr_tag = initial_tag
        for i in range(num_blocks):
            curr_block = message[i*n:(i+1)*n]
            # convert curr_block to int
            curr_block = int(curr_block, 2)
            # convert curr_tag to int
            curr_tag = int(curr_tag, 2)
            prf = PRF(self.security_parameter, self.generator, self.prime_field, key)
            curr_tag=prf.evaluate(curr_block ^ curr_tag)
            curr_tag = bin(curr_tag)[2:].zfill(n)
        return curr_tag

    
    
    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        """
        intiial_tag = self.basic_CBC_MAC(message, self.k1)
        prf = PRF(self.security_parameter, self.generator, self.prime_field, self.k2)
        tag = prf.evaluate(int(intiial_tag, 2))

        return tag
        

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        initial_tag = self.basic_CBC_MAC(message, self.k1)
        prf = PRF(self.security_parameter, self.generator, self.prime_field, self.k2)
        tag = prf.evaluate(int(initial_tag, 2))
        if(tag == int(initial_tag, 2)):
            return True
        else:
            return False
        
print(CBC_MAC(4,144,719,[11,8]).mac("11011101011000111000"))

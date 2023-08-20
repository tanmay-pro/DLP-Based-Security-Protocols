import os
import sys
PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__), 
                  os.pardir)
)
sys.path.append(PROJECT_ROOT)

from PRF.PRF import PRF


class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int, mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        :param mode: Block-Cipher mode of operation
            - CTR
            - OFB
            - CBC
        :type mode: str
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key = key

        pass

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """
        cipher = ""
        cipher += bin(random_seed)[2:].zfill(self.security_parameter)
        num_blocks = len(message)//self.security_parameter
        for i in range (1,num_blocks+1):
            ctr = (random_seed+i)%(2**self.security_parameter)
            message_block=message[(i-1)*self.security_parameter:i*self.security_parameter]
            mes = int(message_block,2)
            c_i = PRF(self.security_parameter, self.generator, self.prime_field, self.key).evaluate(ctr)
            c_i = c_i ^ mes

            c_i = bin(c_i)[2:].zfill(self.security_parameter)
            cipher += c_i
        return cipher
        

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        r = int(cipher[:self.security_parameter],2)
        message = ""
        cipher1 = cipher[self.security_parameter:]
        num_blocks = len(cipher1)//self.security_parameter
        for i in range(1, num_blocks+1):
            ctr = (r+i)%(2**self.security_parameter)
            c_i = int(cipher1[(i-1)*self.security_parameter:(i)*self.security_parameter],2)
            m_i = PRF(self.security_parameter, self.generator, self.prime_field, self.key).evaluate(ctr)
            m_i = m_i ^ c_i
            m_i = bin(m_i)[2:].zfill(self.security_parameter)
            message += m_i
        return message

        

cpatest = CPA(4, 307, 112, 58)
# print(cpatest.enc("1010100011100111", 4))
print(cpatest.dec("01001100100011100100"))

# cpatest = CPA(5, 599, 189, 145)
# print(cpatest.enc("11100011011110010111", 7))

# cpatest = CPA(6, 881, 217, 113)
# print(cpatest.enc("101011011101", 5))

# cpatest = CPA(6, 59, 14, 10)
# print(cpatest.enc("111000101010", 37))

# cpatest = CPA(8, 11, 3, 15)
# print(cpatest.enc("1010100110110111", 8))
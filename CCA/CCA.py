import os
import sys
from typing import Optional
PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__), 
                  os.pardir)
)
sys.path.append(PROJECT_ROOT)

from PRF.PRF import PRF
from CPA.CPA import CPA


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
        # print("intial tag",intiial_tag)
        # print("int",int(intiial_tag, 2))
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
        final_tag = prf.evaluate(int(initial_tag, 2))
        if(tag == final_tag):
            return True
        else:
            return False
 

class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: list[int],
                 cpa_mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: list[int]
        :param cpa_mode: Block-Cipher mode of operation for CPA
            - CTR
            - OFB
            - CBC
        :type cpa_mode: str
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key_cpa = key_cpa
        self.key_mac = key_mac

        pass

    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        :param cpa_random_seed: random seed for CPA encryption
        :type cpa_random_seed: int
        """
        cpa = CPA(self.security_parameter, self.prime_field, self.generator, self.key_cpa)
        cipher = cpa.enc(message, cpa_random_seed)
        cbc = CBC_MAC(self.security_parameter, self.generator, self.prime_field, self.key_mac)
        tag = cbc.mac(cipher)
        bin_tag = bin(tag)[2:].zfill(self.security_parameter)
        final_cipher = cipher + bin_tag
        return final_cipher




        

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        """
        cbc = CBC_MAC(self.security_parameter, self.generator, self.prime_field, self.key_mac)
        tag = cipher[-self.security_parameter:]
        cipher = cipher[:-self.security_parameter]
        print("tag", tag)
        print("cipher", cipher)

        # verify tag

        if(cbc.vrfy(cipher, int(tag, 2))):
            cpa = CPA(self.security_parameter, self.prime_field, self.generator, self.key_cpa)
            message = cpa.dec(cipher)
            print("message",message)
            return message
        else:
            return None

        
ccatest = CCA(7, 41, 17, 34, [10, 9])
print(ccatest.enc("101110101011101000011", 12))
print(ccatest.dec("00011001101101110010110000101111011"))

ccatest = CCA(9, 149, 45, 41, [11, 23])
print(ccatest.enc("010011110000100110101110001100000010010000111", 10))
print(ccatest.dec("000001010010011110010000000010011110100110010010000111000000000"))

ccatest = CCA(6, 17, 7, 5, [17, 3])
print(ccatest.enc("000101001000110010100110000000010100", 18))
print(ccatest.dec("010010101000111101001011001011011110101010111100"))

ccatest = CCA(10, 269, 65, 52, [64, 43])
print(ccatest.enc("011001111000011100111010000010110110100100111100101011000010", 150))
print(ccatest.dec("00100101100110011110100111001110100000101101100000111011001001000101110000000000"))

ccatest = CCA(8, 127, 55, 34, [56, 17])
print(ccatest.enc("111101000100001110100010011101001111010101001111", 100))
print(ccatest.dec("0110010001010001001011110010110010010000110000001100001110110100"))
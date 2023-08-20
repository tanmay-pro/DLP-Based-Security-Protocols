import os
import sys
PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__), 
                  os.pardir)
)
sys.path.append(PROJECT_ROOT)

from PRF.PRF import PRF


class MAC:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, seed: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param seed: k
        :type seed: int
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.seed = seed

    def mac(self, message: str, random_identifier: int) -> str:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        # first, calculate message length n
        # calculate length of seed, this is n
        n = self.security_parameter
        print("n: ", n)
        block_length = n//4
        print("block_length: ", block_length)
        # number of blocks is ceil(message_length/block_length)
        number_of_blocks = 0
        flag = 1 # will tell us whether we require padding or not
        if(len(message)%block_length == 0):
            number_of_blocks = len(message)//block_length
            flag = 0
        else:
            number_of_blocks = len(message)//block_length + 1
        print("number_of_blocks: ", number_of_blocks)
        #initialize an array of size number_of_blocks*block_length
        message_array = [0]*(number_of_blocks*block_length)
        print(len(message_array))
        # show message array
        # copy message to message_array
        for i in range(len(message)):
            message_array[i] = message[i]
        # if flag is 1, then we need to pad the message
        if(flag == 1):
            message_array[len(message)] = '1'
        print("message_array: ", message_array)
        final_tag = bin(random_identifier)[2:].zfill(n//4)
        for i in range(1,number_of_blocks+1):
            print("i = ", i)
            bin_random_identifier = bin(random_identifier)[2:].zfill(n//4)
            bin_number_of_blocks = bin(number_of_blocks)[2:].zfill(n//4)
            bin_i = bin(i)[2:].zfill(n//4)
            print("bin_random_identifier: ", bin_random_identifier, "bin_number_of_blocks: ", bin_number_of_blocks, "bin_i: ", bin_i)
            # take the ith block of message_array of length block_length
            block = message_array[(i-1)*block_length:i*block_length]
            # convert block to string
            block = ''.join(block)
            str = bin_random_identifier + bin_number_of_blocks + bin_i + block
            print(str)
            # convert str to int
            str = int(str, 2)
            print("int(str): ", str)
            # evaluate the PRF at str
            tag = PRF(self.security_parameter, self.generator, self.prime_field, self.seed).evaluate(str)
            print("tag: ", tag)
            # convert tag to binary string
            tag = bin(tag)[2:].zfill(n)
            # append tag to final_tag
            final_tag = final_tag + tag
        
        return final_tag

            


    def vrfy(self, message: str, tag: str) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: str
        """
        # first, calculate message length n
        n = self.security_parameter
        block_length = n//4
        # r is first n//4 bits of tag
        r = tag[:n//4]
        # run mac on message and r
        new_tag = self.mac(message, int(r, 2))
        # compare new_tag and tag
        if(new_tag == tag):
            return True
        else:
            return False
        

# print(MAC(12, 107, 39, 120).mac('110101', 2))
# print(MAC(16, 499, 145, 179).mac('100001011111', 13))

print(MAC(28,617,150,123).mac('111011101100101000000',2))
import os
import sys
PROJECT_ROOT = os.path.abspath(os.path.join(
                  os.path.dirname(__file__), 
                  os.pardir)
)
sys.path.append(PROJECT_ROOT)
class DLP:
    def __init__(self, generator: int = 3, prime_field: int = 2425967623052370772757633156976982469681):
        """
        initialize the discrete logarithm problem prime field (Z_p*) and generator
        """
        self.generator = generator
        self.prime_field = prime_field 

    def calculate(self, x: int) -> int:
        """
        Solve the discrete logarithm problem
        """
        return pow(self.generator, x, self.prime_field) # perform generator^x mod prime_field

    def hard_core_predicate(self, x: int) -> bool:
        """
        return hard-core predicate (MSB) of the input
        """
        # return 1 if x > prime_field / 2 else 0
        return 1 if x >= (self.prime_field -1)/ 2 else 0 # standard hard core predicate for the discrete logarithm problem

class PRG:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int):
        """
        initialize the pseudo-random generator
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.expansion_factor = expansion_factor
    
    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """

        f = DLP(self.generator, self.prime_field) # create a one-way function based on the discrete logarithm problem
        sigma = ""
        y=seed
        for i in range(self.expansion_factor):
            # calculate the discrete logarithm problem
            hcp = f.hard_core_predicate(y)
            y = f.calculate(seed)
            # print("y = ", y)
            # print("hcp = ", hcp)
            sigma += str(hcp)
            # print("pseudo_random_string = ", sigma)
            seed = y
        # pre append bin(y) to pseudo_random_string
        return sigma
            
# main
if __name__ == "__main__":
    # take input for security parameter, generator, prime field, expansion factor and seed all comma separated
    security_parameter, generator, prime_field, expansion_factor, seed = map(int, input().split(","))
    # create a pseudo-random generator
    prg = PRG(security_parameter, generator, prime_field, expansion_factor)
    # generate the pseudo-random bit-string
    pseudo_random_string = prg.generate(seed)
    print("pseudo_random_string = ", pseudo_random_string)


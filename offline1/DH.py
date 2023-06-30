import random


class DiffieHellman:
    def __init__(self):
        pass

    def is_prime(self, n, k=5):
        if n <= 1:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # n is odd at this point
        # Find s, d such that: n-1 = 2^s * d, where s > 0, d is odd
        s, d = 0, n - 1
        while d % 2 == 0:
            s += 1
            d //= 2

        # Perform the Miller-Rabin primality test k times
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)

            y = 0
            for _ in range(s):
                y = pow(x, 2, n)
                if y == 1 and x != 1 and x != n - 1:
                    return False
                x = y

            if y != 1:
                return False

        return True

    def get_modulus_p(self, k: int) -> int:
        """Generate a safe prime with length of k bits for modulus p. 

        Args:
            k (int): Number of bits in safe prime

        Returns:
            int: Same prime
        """
        # generate a prime of k-1 bits
        q = self.get_prime(k-1)

        while not self.is_prime(2 * q + 1):
            q = self.get_prime(k-1)

        return 2 * q + 1

    def get_prime(self, k: int) -> int:
        """Generate a prime of k bit width.

        Args:
            k (int): Number of bits in prime

        Returns:
            int: Prime
        """
        min = 1 << (k-1)
        max = (1 << k) - 1

        num = min
        while not self.is_prime(num):
            num = random.randint(min, max)

        return num

    def get_base_g(self, p: int,  min: int, max: int) -> int:
        """Generate a modular base that is a primitive root of the provided `p`.

        Args:
            p (int): Modulus
            min (int): Minimum g
            max (int): Maximum g

        Returns:
            int: Generated base in [`min`, `max`]
        """


if __name__ == "__main__":
    dh = DiffieHellman()
    p = dh.get_modulus_p(128)
    print(p)
    print("p-1 divisible by 2?", (p-1) % 2 == 0)
    print("Factors of p-1:", (p-1)//2, 2)


"""
    1. generate 2 ints; modulus and base
    modulus:
    take a large prime p as modulus
    - Generate a large prime p which is at least k bits long (take k as param)

    - Generate big randoms, check if its prime using Miller Rabin Primality test

    base: any int g, such that [g^1 to g^(p-1)] mod p forms a residue class of p.
    Since p is large, "any int" brute force search is not feasible. 
    Efficient way of Finding primitive roots use Euler's totient function's prime factors. 
    Prime factors of Phi(p) = p-1
    Tip: Generate p such that finding the prime factors of (p-1) is easy. [p-1 is also a prime?]
    Generate g in [min, max], they are params.
"""

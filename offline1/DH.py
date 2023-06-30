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

        `p` is a safe prime iff, `p-1 = 2 * (p-1)/2`, where `(p-1)/2` is a prime.

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
        min_res = 1 << (k-1)
        max_res = (1 << k) - 1

        res = min_res
        while not self.is_prime(res):
            res = random.randint(min_res, max_res)

        return res

    def get_base_g(self, p: int,  min_g: int, max_g: int) -> int:
        """Generate a modular base in [`min_g`, `max_g`] < `p` that is a primitive root of `p`. 
        Here `p` has to be a safe prime.

        Args:
            p (int): Modulus (**Safe Prime**)
            min_g (int): Minimum g
            max_g (int): Maximum g

        Returns:
            int: Generated base in [`min`, `max`]
        """
        def is_primitive(g: int) -> bool:
            """Check if `g` is a primitive root of `p`.

            Args:
                g (int): Candidate primitive root

            Returns:
                bool: Whether `g` is a primitive root of `p`
            """
            return pow(g, 2, p) != 1 and pow(g, (p-1)//2, p) != 1

        g = min_g
        while not is_primitive(g):
            g = random.randint(min_g, max_g)

        return g

    def get_private_key(self, key_width: int) -> int:
        """Generate private key of `key_width` bits.

        Args:
            key_width (int): Key width in bits

        Returns:
            int: Private key
        """
        return self.get_prime(key_width)

    def get_public_key(self, p: int, g: int, a: int) -> int:
        """Generate public key from modulus `p`, modular base `g` and private key `a`.

        Args:
            p (int): Modulus
            g (int): Modular base
            a (int): Private key

        Returns:
            int: Public key
        """
        return pow(g, a, p)


if __name__ == "__main__":
    dh = DiffieHellman()

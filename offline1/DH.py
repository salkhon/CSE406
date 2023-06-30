import random
import pandas as pd
import time


class DiffieHellman:
    @classmethod
    def is_prime(cls, n, k=5):
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
            x = cls.modular_pow(a, d, n)

            y = 0
            for _ in range(s):
                y = cls.modular_pow(x, 2, n)
                if y == 1 and x != 1 and x != n - 1:
                    return False
                x = y

            if y != 1:
                return False

        return True

    @classmethod
    def get_modulus_p(cls, k: int) -> int:
        """Generate a safe prime with length of k bits for modulus p. 

        `p` is a safe prime iff, `p-1 = 2 * (p-1)/2`, where `(p-1)/2` is a prime.

        Args:
            k (int): Number of bits in safe prime

        Returns:
            int: Same prime
        """
        # generate a prime of k-1 bits
        q = cls.get_prime(k-1)

        while not cls.is_prime(2 * q + 1):
            q = cls.get_prime(k-1)

        return 2 * q + 1

    @classmethod
    def get_prime(cls, k: int) -> int:
        """Generate a prime of k bit width.

        Args:
            k (int): Number of bits in prime

        Returns:
            int: Prime
        """
        min_res = 1 << (k-1)
        max_res = (1 << k) - 1

        res = min_res
        while not cls.is_prime(res):
            res = random.randint(min_res, max_res)

        return res

    @classmethod
    def get_base_g(cls, p: int,  min_g: int, max_g: int) -> int:
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
            return cls.modular_pow(g, 2, p) != 1 and cls.modular_pow(g, (p-1)//2, p) != 1

        g = min_g
        while not is_primitive(g):
            g = random.randint(min_g, max_g)

        return g

    @classmethod
    def get_private_key(cls, key_width: int) -> int:
        """Generate private key of `key_width` bits.

        Args:
            key_width (int): Key width in bits

        Returns:
            int: Private key
        """
        return cls.get_prime(key_width)

    @classmethod
    def get_public_key(cls, p: int, g: int, a: int) -> int:
        """Generate public key from modulus `p`, modular base `g` and private key `a`.

        Args:
            p (int): Modulus
            g (int): Modular base
            a (int): Private key

        Returns:
            int: Public key
        """
        return cls.modular_pow(g, a, p)

    @classmethod
    def compute_shared_secret_key(cls, B: int, a: int, p: int) -> int:
        """Compute the shared secret key using other side's public key and this side's private key.

        Args:
            A (int): Public key of other side
            b (int): Private key of this side
            p (int): Modulus

        Returns:
            int: Shared key
        """
        return cls.modular_pow(B, a, p)

    @classmethod
    def modular_pow(cls, base: int, exponent: int, modulus: int) -> int:
        if modulus == 1:
            return 0

        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent >>= 1
            base = (base * base) % modulus
        return result


if __name__ == "__main__":
    timings = {
        "k": [],
        "p": [],
        "g": [],
        "a or b": [],
        "A or B": [],
        "shared key": []
    }

    MIN_G = 1 << 100
    MAX_G = 1 << 120
    TEST_CASES = 5

    for k in [128, 192, 256]:
        for _ in range(TEST_CASES):
            timings["k"].append(k)

            starttime = time.time()
            p = DiffieHellman.get_modulus_p(k)
            endtime = time.time()
            timings["p"].append(endtime - starttime)

            starttime = time.time()
            g = DiffieHellman.get_base_g(p, MIN_G, MAX_G)
            endtime = time.time()
            timings["g"].append(endtime - starttime)

            starttime = time.time()
            a = DiffieHellman.get_private_key(k//2)
            endtime = time.time()
            timings["a or b"].append(endtime - starttime)

            b = DiffieHellman.get_private_key(k//2)

            starttime = time.time()
            # A = DiffieHellman.get_public_key(p, g, a)
            B = DiffieHellman.get_public_key(p, g, b)
            endtime = time.time()
            timings["A or B"].append(endtime - starttime)

            starttime = time.time()
            shared_key = DiffieHellman.compute_shared_secret_key(B, a, p)
            endtime = time.time()
            timings["shared key"].append(endtime - starttime)

    timing_df = pd.DataFrame(timings).groupby("k").mean()
    print(timing_df)

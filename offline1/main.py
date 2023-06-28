import numpy as np
import ctypes

sbox = np.zeros((256,), dtype=np.uint8)


def init_aes_sbox(aes_sbox: np.ndarray):
    """Initilizes the passed in AES sbox.

    Args:
        aes_sbox (np.ndarray): AES sbox to be initialized
    """

    def ROTL8(n: np.uint8, shift: np.uint8) -> np.uint8:
        """Left rotate 8 bits of uint.

        Args:
            n (np.uint8): Unsigned 8 bit int to rotate
            shift (np.uint8): Shift amount

        Returns:
            np.uint8: Rotated uint8
        """
        return (n << shift) | (n >> (8 - shift))

    p = np.uint8(1)
    q = np.uint8(1)

    uint8_0x1b = np.uint8(0x1b)
    uint8_0x80 = np.uint8(0x80)
    uint8_0x09 = np.uint8(0x09)
    uint8_0 = np.uint8(0)
    uint8_1 = np.uint8(1)
    uint8_2 = np.uint8(2)
    uint8_3 = np.uint8(3)
    uint8_4 = np.uint8(4)
    uint8_0x63 = np.uint8(0x63)

    is_first = True
    # loop invariant: p * q == 1 in the Galois Field
    while is_first or p != uint8_1:
        is_first = False

        # multiply p by 3
        p = p ^ (p << uint8_1) ^ (uint8_0x1b if p & uint8_0x80 else uint8_0)
        print("p", p)

        # divide q by 3
        q ^= q << uint8_1
        q ^= q << uint8_2
        q ^= q << uint8_4
        q ^= uint8_0x09 if q & uint8_0x80 else uint8_0

        # compute the affine transformation
        xformed = q ^ ROTL8(q, uint8_1) ^ ROTL8(
            q, uint8_2) ^ ROTL8(q, uint8_3) ^ ROTL8(q, uint8_4)

        sbox[p] = xformed ^ uint8_0x63

    sbox[0] = uint8_0x63


if __name__ == "__main__":
    init_aes_sbox(sbox)
    sbox = sbox.reshape((16, 16))
    sbox_hex = np.vectorize(hex)(sbox)
    print(sbox_hex)

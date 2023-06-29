from collections.abc import Callable
from typing import Any, TypeVar
from BitVector import BitVector

T = TypeVar("T")


class AES:
    """Symmetric cryptography system. 
    """
    SBOX = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    INV_SBOX = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )

    MIXER = [
        [BitVector(hexstring="02"), BitVector(hexstring="03"),
         BitVector(hexstring="01"), BitVector(hexstring="01")],
        [BitVector(hexstring="01"), BitVector(hexstring="02"),
         BitVector(hexstring="03"), BitVector(hexstring="01")],
        [BitVector(hexstring="01"), BitVector(hexstring="01"),
         BitVector(hexstring="02"), BitVector(hexstring="03")],
        [BitVector(hexstring="03"), BitVector(hexstring="01"),
         BitVector(hexstring="01"), BitVector(hexstring="02")]
    ]

    INV_MIXER = [
        [BitVector(hexstring="0E"), BitVector(hexstring="0B"),
         BitVector(hexstring="0D"), BitVector(hexstring="09")],
        [BitVector(hexstring="09"), BitVector(hexstring="0E"),
         BitVector(hexstring="0B"), BitVector(hexstring="0D")],
        [BitVector(hexstring="0D"), BitVector(hexstring="09"),
         BitVector(hexstring="0E"), BitVector(hexstring="0B")],
        [BitVector(hexstring="0B"), BitVector(hexstring="0D"),
         BitVector(hexstring="09"), BitVector(hexstring="0E")]
    ]

    MODULUS = BitVector(bitstring='100011011')

    RC = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

    def __init__(self):
        pass

    def encrypt(self, plaintext16: str, key: str) -> str:
        """Encrypt the given text, with the provided key.

        If key has length less than 128 bits, zero pad it. 
        Else if key has length greater than 128, chunk it to 128 or less. 

        Args:
            text (str): Plain text
            key (str): Cipher secret key
        Returns:
            str: Cipher
        """
        if len(key) > 16:
            key = key[:16]

        # chunk or pad text to list 16 char parts
        plaintexts = self.convert_text_to_16_bytes(plaintext16)

        # get list of round key matrices
        round_keys_mats4x4 = self.get_round_keys_matrices(key)

        for plaintext16 in plaintexts:
            # state matric for plain text chunk
            state_mat4x4 = self.convert_list16_to_mat4x4(
                self.convert_str_to_int_list(plaintext16))

            for round in range(10):
                self.compute_round(
                    state_mat4x4, round_keys_mats4x4[round], round)

        return ""

    def compute_round(self, state_mat4x4: list[list[int]], round_key_mat4x4: list[list[int]], round: int) -> list[list[int]]:
        """Compute each round operation on state matrix.

        Args:
            state_mat4x4 (list[list[int]]): State matrix of this round
            round_key_mat4x4 (list[list[int]]): Round key matrix for this round
            round (int): This round

        Returns:
            list[list[int]]: Computed state matrix after this round
        """
        # add roundkey
        state_mat = self.apply_elemwise4x4(
            state_mat4x4, round_key_mat4x4, lambda x, y: x ^ y)

        # byte substitution
        state_mat = [[AES.SBOX[b] for b in sublist] for sublist in state_mat]

        # shift row
        for row in range(1, 4):
            state_mat[row] = self.left_rotate_word(state_mat[row], amount=row)

        # mix column
        state_mat = [[BitVector(intVal=i) for i in row] for row in state_mat]
        state_mat = self.apply_elemwise4x4(
            AES.MIXER, state_mat, lambda x, y: x.gf_multiply_modular(y, AES.MODULUS, 8))
        state_mat = [[bv.int_val() for bv in row] for row in state_mat]

        return state_mat

    def apply_matmulwise4x4(self, A: list[list[T]], B: list[list[T]],
                            func: Callable[[T, T], T]) -> list[list[T]]:
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    pass

    def apply_elemwise4x4(self, A: list[list[T]], B: list[list[T]],
                          func: Callable[[T, T], T]) -> list[list[T]]:
        """Compute element-wise operation for two matrices.

        Args:
            A (list[list[int]]): Matrix A
            B (list[list[int]]): Matrix B

        Returns:
            list[list[int]]: result matrix
        """
        res: list[list[T]] = []
        for i in range(4):
            res.append([])
            for j in range(4):
                res[i].append(func(A[i][j], B[i][j]))
        return res

    def get_round_keys_matrices(self, key: str) -> list[list[list[int]]]:
        """Generate round keys from provided key using KEY EXPANSION, and return a list of matrices that are the
        column major matrices suitable for encryption.

        Args:
            key: str: Key string

        Returns:
            list[list[list[int]]]: List of 4x4 column major matrices of each key
        """
        # List of 4x4 round key mats, for each round
        round_keys_mats4x4: list[list[list[int]]] = []

        # Convert key words to matrices
        round_keys = self.key_expansion(key)
        for i in range(0, 44, 4):
            # get 4 words at a time to get 16 byte list
            round_keys_mats4x4.append(self.convert_list16_to_mat4x4(
                self.flatten_list_of_list(round_keys[i:i+4])))

        return round_keys_mats4x4

    def flatten_list_of_list(self, list_o_list: list[list]) -> list:
        """Convert list of list to list. 

        Args:
            list_o_list (list[list]): List of list

        Returns:
            list: Flattened list
        """
        return [elem for sublist in list_o_list for elem in sublist]

    def convert_list16_to_mat4x4(self, list16: list) -> list[list]:
        """Convert a list of 16 elements to 4x4 matrix format, in **column major** order. 

        Args:
            list16 (list): List of 16 elements

        Returns:
            list[list]: Column major matrix 4x4
        """
        mat = [[0] * 4 for row in range(4)]
        for idx, elem in enumerate(list16):
            mat[idx % 4][idx // 4] = elem

        return mat

    def decrypt(self, cipher: str, key: str) -> str:
        """Decrpypt the given cipher with the given key.

        Args:
            cipher (str): Cipher text
            key (str): Key

        Returns:
            str: Plain text
        """
        return ""

    def convert_text_to_16_bytes(self, plaintext: str) -> list[str]:
        """Convert text of any length to list of 16 bytes textx (128 bits).

        Args:
            text (str): text of any length

        Returns:
            list[str]: List of 16 byte texts
        """

        def pad_smaller_text(text: str) -> str:
            return '\0' * (16 - len(text)) + text

        texts = []
        if len(plaintext) < 16:
            texts.append(pad_smaller_text(plaintext))
        elif len(plaintext) > 16:
            texts.extend([plaintext[i:i+16]
                         for i in range(0, len(plaintext) - 16, 16)])
            texts.append(
                pad_smaller_text(
                    plaintext[(len(plaintext) // 16) * 16:]))

        return texts

    def convert_16_byte_key_to_4_byte_words(self, key: str) -> list[str]:
        """Convert 16 bytes key (HAS TO BE 16 BYTE KEY) to a list of 4 byte words.

        Args:
            key (str): 16 byte keys

        Returns:
            list[str]: list of 4 key words, each word having 4 bytes
        """
        return [key[i:i+4] for i in range(0, len(key), 4)]

    def convert_str_to_int_list(self, key: str) -> list[int]:
        """Convert string to list of unicode ints.

        Args:
            key (str): Key string

        Returns:
            list[int]: list of UNICODE ints of the chars
        """
        return [ord(c) for c in key]

    def left_rotate_word(self, word: list[int], amount=1) -> list[int]:
        """Left rotate word by 1. `word` must have length greater than 1.

        Args:
            word (list[int]): word to be rotated

        Returns:
            str: Left rotated word
        """
        return word[amount:] + word[0:amount]

    def get_next_round_key(self, key: list[list[int]], round: int) -> list[list[int]]:
        """Get next round's key from provided key.

        Args:
            key: list[list[int]]: 4x4 matrix of words in the key
            round: int: The round number

        Returns:
            list[list[int]]: The 4x4 matrix for the next round's key
        """

        def xor_words(word1: list[int], word2: list[int]) -> list[int]:
            """Elementwise XOR between two key words. 

            Args:
                word1 (list[int]): Word 1
                word2 (list[int]): Word 2

            Returns:
                list[int]: Resulting word after XOR 
            """
            return list(map(lambda x, y: x ^ y, word1, word2))

        w0, w1, w2, w3 = key
        gw3 = self.left_rotate_word(w3)

        # byte substitution
        gw3 = [AES.SBOX[b] for b in gw3]

        # Adding round constant (XORing 1 to left most char of gw3)
        gw3[0] ^= AES.RC[round]

        # next key
        w4 = xor_words(w0, gw3)
        w5 = xor_words(w4, w1)
        w6 = xor_words(w5, w2)
        w7 = xor_words(w6, w3)

        return [w4, w5, w6, w7]

    def key_expansion(self, key: str) -> list[list[int]]:
        """Expand 16 byte key to 44 keys each of 4 words.

        Args:
            key (str): Key string of 16 characters

        Returns:
            list[list[int]]: List of 44 4-byte words
        """

        words = self.convert_16_byte_key_to_4_byte_words(key)
        words = [self.convert_str_to_int_list(word) for word in words]

        # list of words (list[int])
        key_words: list[list[int]] = [*words]

        # todo: variable round of keys for variable keys
        for round in range(10):
            next_words = self.get_next_round_key(words, round)
            key_words.extend(next_words)
            words = next_words

        return key_words

    def convert_word_to_hex(self, word: list[int]) -> list[str]:
        return [hex(w) for w in word]


if __name__ == "__main__":
    aes = AES()
    words = aes.key_expansion("Thats my Kung Fu")
    for i in range(44):
        print(aes.convert_word_to_hex(words[i]))

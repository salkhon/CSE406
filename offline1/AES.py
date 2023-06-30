from collections.abc import Callable
from typing import Any, TypeVar
from BitVector import BitVector
import numpy as np
import numpy.typing as npt


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

    def encrypt(self, plaintext: str, key: str, verbose=False) -> str:
        """Encrypt the given text, with the provided key.

        If key has length less than 128 bits, zero pad it. 
        Else if key has length greater than 128, chunk it to 128 or less. 

        Args:
            text (str): Plain text
            key (str): Cipher secret key
        Returns:
            str: Cipher
        """
        # if key is longer than 16, truncate
        if len(key) > 16:
            key = key[:16]

        # chunk or pad text to list 16 char parts
        plaintexts = self.convert_text_to_16_bytes(plaintext)

        # get list of 4x4 round key matrices
        round_key_mats = self.key_expansion(key)

        # for each 16 character plain text, do all rounds of encryption
        encryption = ""
        state_mat = np.zeros(shape=(4, 4), dtype=np.uint8)
        for plaintext16 in plaintexts:
            # state matrix for plain text chunk
            state_mat = self.convert_16_char_str_to_4x4_mat(plaintext16)
            # self.display_nparray_in_hex(state_mat)

            for round in range(11):
                state_mat = self.compute_round_encrypt(
                    state_mat, round_key_mats[round], round)
                self.display_nparray_in_hex(state_mat)

            encryption += "".join([hex(elem)[2:].zfill(2)
                                   for elem in state_mat.flatten(order="F")])

        return encryption

    def decrypt(self, cipher: str, key: str) -> str:
        """Decrpypt the given cipher (in hex string format) with the given key.

        Args:
            cipher (str): Cipher text in hex string format
            key (str): Key

        Returns:
            str: Plain text
        """
        # if key is longer than 16, truncate
        if len(key) > 16:
            key = key[:16]

        # chunk or pad text to list 16 char parts
        cipher_ascii_str = BitVector(hexstring=cipher).get_bitvector_in_ascii()
        ciphertexts = self.convert_text_to_16_bytes(cipher_ascii_str)

        # get list of 4x4 round key matrices
        round_key_mats = self.key_expansion(key)
        round_key_mats.reverse()

        # for each 16 character plain text, do all rounds of encryption
        decryption = ""
        state_mat = np.zeros(shape=(4, 4), dtype=np.uint8)
        for cipher16 in ciphertexts:
            # state matrix for plain text chunk
            state_mat = self.convert_16_char_str_to_4x4_mat(cipher16)

            for round in range(11):
                state_mat = self.compute_round_decrypt(
                    state_mat, round_key_mats[round], round)

            decryption += "".join([chr(elem)
                                  for elem in state_mat.flatten(order="F")])

        return decryption.replace("\0", "")

    def compute_round_decrypt(self, state_mat: npt.NDArray[np.uint8], round_key_mat: npt.NDArray[np.uint8], round: int) -> npt.NDArray[np.uint8]:
        if round == 0:
            return state_mat ^ round_key_mat
        else:
            state_mat_res = state_mat.copy()

            # shift row
            for row in range(1, 4):
                state_mat_res[row, :] = np.roll(
                    state_mat_res[row, :], shift=row)

            # sub bytes
            state_mat_res = self.byte_substitution(state_mat_res, AES.INV_SBOX)

            # add round key
            state_mat_res ^= round_key_mat

            # inverse mix column
            if round != 10:
                state_mat_res = self.mix_column(state_mat_res, AES.INV_MIXER)

            return state_mat_res

    def compute_round_encrypt(self, state_mat: npt.NDArray[np.uint8], round_key_mat: npt.NDArray[np.uint8], round: int) -> npt.NDArray[np.uint8]:
        """Compute each round of encryption on the state matrix and return the resulting state matrix.

        Args:
            state_mat (npt.NDArray[np.uint8]): 4x4 state matrix
            round_key_mat (npt.NDArray[np.uint8]): 4x4 round key matrix
            round (int): round number

        Returns:
            npt.NDArray[np.uint8]: resulting state matrix
        """
        if round == 0:
            # add roundkey
            return state_mat ^ round_key_mat
        else:
            state_mat_res = state_mat.copy()

            # byte substitution
            state_mat_res = self.byte_substitution(state_mat_res)

            # shift row
            for row in range(1, 4):
                state_mat_res[row, :] = np.roll(
                    state_mat_res[row, :], shift=-row)

            # mix column
            if round != 10:  # todo: variable rounds
                state_mat_res = self.mix_column(state_mat_res)

            # add round key
            state_mat_res ^= round_key_mat

            return state_mat_res

    def mix_column(self, state_mat: npt.NDArray[np.uint8], MX=MIXER) -> npt.NDArray[np.uint8]:
        """Perform the mix column step of encryption on the state matrix.

        Args:
            state_mat (npt.NDArray[np.uint8]): State matrix

        Returns:
            npt.NDArray[np.uint8]: Result
        """
        state_mat_bitvec = state_mat.tolist()
        state_mat_bitvec = [
            [BitVector(intVal=elem) for elem in sublist] for sublist in state_mat_bitvec]

        result_mat = np.zeros(shape=(4, 4), dtype=np.uint8)
        # do matmul
        for i in range(4):
            for j in range(4):
                r = 0
                for k in range(4):
                    r ^= MX[i][k].gf_multiply_modular(
                        state_mat_bitvec[k][j], AES.MODULUS, 8).int_val()
                result_mat[i, j] = r

        return result_mat.astype(np.uint8)

    def convert_text_to_16_bytes(self, plaintext: str) -> list[str]:
        """Convert text of any length to list of 16 bytes texts (128 bits). If smaller, pad it to 16 chars, 
        if larger, chunk it to a list of 16 character chunks.

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
                    plaintext[((len(plaintext)-1) // 16) * 16:]))
        else:
            texts.append(plaintext)

        return texts

    def convert_16_char_str_to_4x4_mat(self, key: str) -> npt.NDArray[np.uint8]:
        """Convert 16 character key (HAS TO BE 16 character KEY) to a 4x4 column major matrix of
        4 4-character words, whose UNICODE numbers are stored in the matrix.

        Args:
            key (str): 16 byte keys

        Returns:
            npt.NDArray[np.uint8]: 2D column wise matrix, each column having the UNICODE number of a 4 
            character word
        """

        words = [self.convert_str_to_unicode_int_array(
            key[i:i+4]) for i in range(0, len(key), 4)]
        return np.array(words).T

    def convert_str_to_unicode_int_array(self, key: str) -> npt.NDArray[np.uint8]:
        """Convert string to an array of unicode ints.

        Args:
            key (str): Key string

        Returns:
            npt.NDArray[np.uint8]: array of UNICODE ints of the chars
        """
        return np.array([ord(c) for c in key])

    def byte_substitution(self, mat: npt.NDArray[np.uint8], box=SBOX) -> npt.NDArray[np.uint8]:
        return np.vectorize(lambda elem: box[elem])(mat)

    def get_next_round_key(self, key_word_mat: npt.NDArray[np.uint8], round: int) -> npt.NDArray[np.uint8]:
        """Get next round's key from provided key.

        Args:
            key_word_mat: npt.NDArray[np.uint8]: 4x4 matrix of words in the key, in column major order
            round: int: The round number

        Returns:
            npt.NDArray[np.uint8]: The 4x4 matrix for the next round's key
        """
        gw3 = np.roll(key_word_mat[:, 3], shift=-1)  # -1 for left shift by 1

        # byte substitution
        gw3: npt.NDArray[np.uint8] = self.byte_substitution(gw3)

        # Adding round constant (XORing 1 to left most char of gw3)
        gw3[0] ^= AES.RC[round]

        # next key
        w4 = key_word_mat[:, 0] ^ gw3
        w5 = w4 ^ key_word_mat[:, 1]
        w6 = w5 ^ key_word_mat[:, 2]
        w7 = w6 ^ key_word_mat[:, 3]

        return np.array([w4, w5, w6, w7], dtype=np.uint8).T

    def key_expansion(self, key: str) -> list[npt.NDArray[np.uint8]]:
        """Expand 16 byte key to 11 4x4 key matrix, each column of a matrix represents a word.

        Args:
            key (str): Key string of 16 characters

        Returns:
            list[npt.NDArray[np.uint8]]: List of 11 4x4 round key matrices
        """

        key_mat = self.convert_16_char_str_to_4x4_mat(key)

        # list of key matrices for each round
        round_key_mats: list[npt.NDArray[np.uint8]] = [key_mat]

        # todo: variable round of keys for variable keys
        for round in range(10):
            next_key_mat = self.get_next_round_key(key_mat, round)
            round_key_mats.append(next_key_mat)
            key_mat = next_key_mat

        return round_key_mats

    def display_nparray_in_hex(self, array: np.ndarray):
        hex_func = np.vectorize(hex)
        print(hex_func(array))

    def convert_ascii_to_hex_string(self, ascii: str) -> str:
        return "".join([hex(ord(char))[2:].zfill(2)
                        for char in ascii])


if __name__ == "__main__":
    aes = AES()
    KEY = "Thats my Kung Fu more stuff"
    TEXT = "Two One Nine Two Radio Alpha joseph bravo plane gonjo broken something run out of things to say"
    enc = aes.encrypt(plaintext=TEXT, key=KEY)
    print(enc)
    dec = aes.decrypt(enc, KEY)
    print(dec)

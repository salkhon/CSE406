import socket
from AES import AES, convert_hex_to_ascii_string, convert_int_to_byte_level_ascii
from DH import DiffieHellman


class SecureChannel:
    def __init__(self, sock: socket.socket, k=128, bufsize=1024):
        """Create an encrypted channel. Wrapper around the socket. 

        Args:
            sock (socket.socket): Socket
            k (int, optional): Key bitwidth. Defaults to 128.
            bufsize (int, optional): Send Receive buffer size. Defaults to 1024.
        """
        self.sock = sock
        self.k = k
        self.BUFSIZE = bufsize

        self.p: int
        self.g: int
        self.a: int
        self.A: int
        self.B: int
        self.shared_secret: int
        self.aes: AES

    def create_keys_serverside(self) -> tuple[int, int]:
        """Create modulus, base using Diffie-Hellman for server side. The server
        fixes the p, g values. The client receives and sets those values. 

        Returns:
            tuple: Tuple containing p, g of Diffie-Hellman
        """
        p = DiffieHellman.get_modulus_p(128)
        min_g = 1 << self.k-50
        max_g = 1 << self.k-10
        g = DiffieHellman.get_base_g(p, min_g, max_g)

        return p, g

    def _send_int_as_str(self, i: int):
        return self.sock.send(str(i).encode())

    def _recv_intstr_as_int(self) -> int:
        return int(self.sock.recv(self.BUFSIZE).decode())

    def setup_serverside(self):
        """Establishes secure server connection, sends the client the values of p and g. Then receives public key 
        from client. Also sends back server side public key. Sets up AES encyptor.
        """
        # create Diffie-Hellman configs on the server
        self.p, self.g = self.create_keys_serverside()

        # send the configs to the client
        self._send_int_as_str(self.p)
        self._recv_intstr_as_int()  # client OK
        self._send_int_as_str(self.g)

        # setup server's private and public key
        self.a = DiffieHellman.get_private_key(self.k)
        self.A = DiffieHellman.get_public_key(self.p, self.g, self.a)

        # receive clients public key
        self.B = self._recv_intstr_as_int()

        # compute shared secret and initialize AES
        self.shared_secret = DiffieHellman.compute_shared_secret_key(
            self.B, self.a, self.p)
        self.shared_secret |= 1 << (self.k-1)  # making bitwidth 128 bits
        print("Server SecureChannel setting shared secret:", self.shared_secret)

        self.aes = AES(convert_int_to_byte_level_ascii(self.shared_secret))

        # sending the server's public key
        self.sock.send(str(self.A).encode())

    def setup_clientside(self, address: tuple[str, int]):
        """Establishes secure client connection. Client first recieves the Diffie-Hellman p and g values
        from the Server. Then, sends the client's public key, and receives back the server's public
        key. Sets up AES encryptor.

        Args:
            address (tuple[str, int]): IP addres, Port
        """
        self.sock.connect(address)

        # receive Diffie-Hellman configuration from server
        self.p = self._recv_intstr_as_int()
        self._send_int_as_str(0)  # OK
        self.g = self._recv_intstr_as_int()

        # setup client's private, and public key
        self.a = DiffieHellman.get_private_key(self.k)
        self.A = DiffieHellman.get_public_key(self.p, self.g, self.a)

        # send client's public key to server
        self.sock.send(str(self.A).encode())

        # receive server's public key
        self.B = int(self.sock.recv(self.BUFSIZE).decode())

        # compute shared key and initialize AES
        self.shared_secret = DiffieHellman.compute_shared_secret_key(
            self.B, self.a, self.p)
        self.shared_secret |= 1 << (self.k-1)  # making bitwidth 128 bits
        print("Client SecureChannel setting shared secret:", self.shared_secret)

        self.aes = AES(convert_int_to_byte_level_ascii(self.shared_secret))

    def send(self, message: str) -> int:
        """Send encrypted data through socket.

        Args:
            data (str): Message string

        Returns:
            int: Number of bytes sent
        """
        hex_string = self.aes.encrypt(message)
        print("SecureChannel sending encrypted message:", hex_string)
        return self.sock.send(hex_string.encode())

    def recv(self) -> str:
        """Receive encrypted message and decrypt it.

        Returns:
            str: Decrypted message
        """
        hex_string = self.sock.recv(self.BUFSIZE).decode()
        print("SecureChannel received encrypted message:", hex_string)
        return self.aes.decrypt(hex_string)

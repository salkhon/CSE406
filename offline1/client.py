import socket
from secure import SecureChannel

PORT = 12345

if __name__ == "__main__":
    with socket.socket() as sock:
        client_secure_channel = SecureChannel(sock)
        client_secure_channel.setup_clientside(("localhost", PORT))

        while True:
            message = input("Client: ")
            client_secure_channel.send(message)

            print()

            reply = client_secure_channel.recv()
            print("Server:", reply)

            print()

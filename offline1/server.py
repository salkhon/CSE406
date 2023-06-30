import socket
from secure import SecureChannel

PORT = 12345

if __name__ == "__main__":
    with socket.socket() as server_sock:
        server_sock.bind(("localhost", PORT))
        server_sock.listen(5)

        client_sock, _ = server_sock.accept()
        client_secure_channel = SecureChannel(client_sock)
        client_secure_channel.setup_serverside()

        while True:
            # server first receives
            message = client_secure_channel.recv()
            print("Client:", message)

            print()

            reply = input("Server: ")
            client_secure_channel.send(reply)

            print()

from email import message
from dh_support import *
import socket
import sys


def run_client(host, port):
    port = int(port)
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.connect((host, port))
    client = Client(serverSocket)
    print("Connected to server")
    (result, message) = client.establishTunnel()
    if not result:
        print(f"Error establishing tunnel: {message.decode()}")
        return
    else:
        print("Established tunnel.")
    password = bytes.fromhex(input("Password in hex: "))
    client.send(password)
    print(f"Received from server: {client.receive()[1].decode()}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <hostname> <port>")
        exit()

    run_client(sys.argv[1], sys.argv[2])

#!/usr/bin/python3
import socket
import logging
import threading
import sys

from dh_support import *

(HOST, PORT) = ("0.0.0.0", 1337)

PASSWORD_FILENAME = os.path.join(os.path.dirname(__file__), "password.bin")
FLAG_FILENAME = os.path.join(os.path.dirname(__file__), "flag.txt")


def handleConnection(clientSocket):
    try:
        command = recvMessage(clientSocket)
        if command == PROTOCOL_MAGIC:
            sendMessage(clientSocket, PROTOCOL_MAGIC)
            # start protocol
            status = False

            server = Server(clientSocket)
            while not status:
                (status, key_used) = server.establishTunnel()
                key_hex = "".join(["%02x" % x for x in key_used])
                logging.info(f"Established tunnel: {status} with key {key_hex}")
            (result, password) = server.receive()
            with open(PASSWORD_FILENAME, "rb") as f:
                actual_password = f.read()
            if password[: len(actual_password)] != actual_password:
                server.send(b"Bad password")
                clientSocket.close()
                return
            else:
                with open(FLAG_FILENAME, "r") as f:
                    server.send(f"Congratulations. Your flag is: {f.read()}".encode())
                    logging.info("Success")
                    clientSocket.close()
                    return

        else:
            sendMessage(clientSocket, b"Bad client")
            logging.error("Bad client connected")
        clientSocket.close()
        return
    except (TooMuchData, NotEnoughData):
        logging.error("Received malformed packet")
        clientSocket.close()
        return
    except (Server.NoTunnel):
        logging.error("Tried to send password without establishing tunnel")
        clientSocket.close()
    except ConnectionResetError:
        logging.error("Connection reset by client")
        return


def startServer():

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
        datefmt="%m-%d %H:%M",
        filename="server.log",
        filemode="w",
    )

    if not os.path.isfile(PASSWORD_FILENAME):
        logging.fatal("Password file not found")
        return
    with open(PASSWORD_FILENAME, "rb") as f:
        if len(f.read()) == 0:
            logging.fatal("Password file is empty")
            return

    if not os.path.isfile(FLAG_FILENAME):
        logging.fatal("FLAG file not found")
        return

    with open(FLAG_FILENAME, "r") as f:
        if len(f.read()) == 0:
            logging.fatal("FLAG file is empty")
            return
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    serverSocket.bind((HOST, PORT))
    serverSocket.listen()
    logging.info(f"Started listenning on {HOST}:{PORT}")
    while True:

        try:
            (clientSocket, address) = serverSocket.accept()
            logging.info(f"Accepted connection from {address}")
            threading.Thread(target=handleConnection, args=(clientSocket,)).start()
        except KeyboardInterrupt:
            print("Exiting...")
            logging.info("Exiting due to keyboard interrupt")
            return
        except Exception as e:
            logging.info(f"Caught exception: {repr(e)}")
            print(f"Caught exception: {repr(e)}", file=sys.stderr)


if __name__ == "__main__":
    startServer()

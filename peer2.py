import socket
import threading


def receive_messages(connection):
    while True:
        try:
            message = connection.recv(1024).decode('utf-8')
            if not message:
                print("\nPeer disconnected.")
                break
            print(f"\n{message}")
        except:
            print("\nConnection lost.")
            break


def send_messages(connection, user_name):
    while True:
        message = input("")
        if message.lower() == 'quit':
            break
        full_message = f"{user_name}: {message}"
        try:
            connection.send(full_message.encode('utf-8'))
        except:
            print("\nFailed to send message. Connection might be lost.")
            break


def attempt_connection(peer_socket, target=('localhost', 8080)):
    try:
        peer_socket.connect(target)
        return True
    except ConnectionRefusedError:
        return False


def create_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    print("Waiting for connection on port 8080.")
    connection, address = server_socket.accept()
    print(f"Connection established with {address}")
    return connection


if __name__ == "__main__":
    user_name = input("Enter your name: ")

    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if not attempt_connection(peer_socket):
        peer_socket = create_server()
    else:
        print("Connected to the peer.")

    # Starting threads for sending and receiving messages
    receiver_thread = threading.Thread(target=receive_messages, args=(peer_socket,))
    sender_thread = threading.Thread(target=send_messages, args=(peer_socket, user_name,))

    receiver_thread.start()
    sender_thread.start()

    receiver_thread.join()
    sender_thread.join()

    peer_socket.close()
    print("Chat ended.")

import socket

HOST, PORT = 'localhost', 9999
data = {'test': 9}
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect((HOST, PORT))
    sock.sendall(bytes(str(data) + '\n', 'utf-8'))

    received = str(sock.recv(1024), 'utf-8')
finally:
    sock.close()
    print('Sent:     {}'.format(data))
    print('Received: {}'.format(received))

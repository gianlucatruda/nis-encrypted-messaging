import socket
from collections import deque
from threading import Thread
from time import sleep


class NetworkInterface:
    """Defines the communication between a client and server"""

    def __init__(self, host='localhost', port=1302, server=False):
        self.send_buffer = deque()      # queue of message objects to be sent
        self.recv_buffer = deque()      # queue of message objects received
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_closed = False

        if server:
            self.server_socket.bind((host, port))
            self.server_socket.listen(1)  # how many clients we are expecting
            print('Listening to ', host, ' on port ', port)
            self.server_socket, address = self.server_socket.accept()
            print('Connected to ', str(address))
        else:
            self.server_socket.connect((host, port))
            print('Connected to  server ', host, ' on port ', port)

        # Create threads for sending and receiving messages
        self.send_thread = Thread(target=self._send_messages)
        self.recv_thread = Thread(target=self._receive_messages)
        # Start threads
        self.send_thread.start()
        self.recv_thread.start()

    def _send_messages(self):
        """ Continuously checks buffer for messages and sends them """
        while True:
            if self.is_closed:
                break
            if len(self.send_buffer) > 0:
                msg = self.send_buffer.popleft()       # get first message in buffer
                data = msg.encode()                    # convert it to byte-data
                self.server_socket.send(data)          # send it through socket
            sleep(0.1)

    def _receive_messages(self):
        """ Continuously listens for messages and adds them to the buffer """
        while True:
            if self.is_closed:
                break
            data = self.server_socket.recv(4096)       # receive byte data
            msg = data.decode()                        # convert data to text
            self.recv_buffer.append(msg)               # add message to buffer
            sleep(0.1)

    def send(self, msg):
        """ Adds a message to the send buffer. It will be sent when it reaches
        the front of the queue """
        self.send_buffer.append(msg)

    def receive(self):
        """ Returns the first message in the receive buffer, or None if the
        buffer is empty """
        if len(self.recv_buffer) > 0:
            return self.recv_buffer.popleft()
        else:
            return None

    def blocking_receive(self):
        """ Returns the first message in the receive buffer, or blocks until
        a message is received """
        msg_recv = self.receive()
        while msg_recv is None:
            msg_recv = self.receive()
        return msg_recv

    def close_connection(self):
        """ Closes the socket connection.
        """
        if len(self.send_buffer) > 0 or len(self.recv_buffer) > 0:
            sleep(3) # Allow final items in buffers to be flushed
        self.is_closed = True
        self.recv_thread.join()
        self.send_thread.join()
        self.server_socket.close()

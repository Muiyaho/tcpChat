import sys
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, \
    QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
import socket

#IP와 포트를 사용하여 채팅 서버
def start_chat_server(ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(1)
    return server #채팅 서버 소켓을 반환

#채팅 서버에서 클라이언트의 연결을 수락
def accept_connections(server):
    while True:
        client_socket, client_addr = server.accept()
        print(f"{client_addr} has connected.")
        return client_socket

class ReceiveThread(QThread):
    received_message = pyqtSignal(str, str)

    def __init__(self, socket):
        super().__init__()
        self.socket = socket

    def run(self):
        while True:
            try:
                data = self.socket.recv(1024)
                message = data.decode('utf-8', errors='replace')
                sender_ip = self.socket.getpeername()[0][:6]
                self.received_message.emit(sender_ip, message)
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.socket.close()
                break

class ChatWindow(QWidget):
    def __init__(self, socket):
        super().__init__()

        self.socket = socket

        self.init_ui()

        self.receive_thread = ReceiveThread(self.socket)
        self.receive_thread.received_message.connect(self.display_received_message)
        self.receive_thread.start()

    def init_ui(self):
        self.setWindowTitle('채팅')

        vbox = QVBoxLayout()

        self.chat_text = QTextEdit()
        self.chat_text.setReadOnly(True)
        vbox.addWidget(self.chat_text)

        hbox = QHBoxLayout()

        self.message_entry = QLineEdit()
        self.message_entry.returnPressed.connect(self.send_message)
        hbox.addWidget(self.message_entry)

        send_button = QPushButton('전송')
        send_button.clicked.connect(self.send_message)
        hbox.addWidget(send_button)

        clear_button = QPushButton('지우기')
        clear_button.clicked.connect(self.clear)
        hbox.addWidget(clear_button)

        close_button = QPushButton('닫기')
        close_button.clicked.connect(self.close)
        hbox.addWidget(close_button)

        vbox.addLayout(hbox)

        self.setLayout(vbox)

    def send_message(self):
        message = self.message_entry.text()
        self.message_entry.clear()

        if message:
            sender_ip = self.socket.getsockname()[0][:6]
            self.chat_text.append(f"{sender_ip}: {message}")

            try:
                self.socket.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error sending message: {e}")
                self.socket.close()

    def display_received_message(self, sender_ip, message):
        self.chat_text.append(f"{sender_ip}: {message}")

    def closeEvent(self, event):
        self.socket.close()
        self.receive_thread.quit()
        self.receive_thread.wait()

    def clear(self):
        self.chat_text.clear()

class ConnectWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('접속')

        vbox = QVBoxLayout()

        vbox.addWidget(QLabel('IP:'))

        self.ip_entry = QLineEdit()
        vbox.addWidget(self.ip_entry)

        vbox.addWidget(QLabel('Port:'))

        self.port_entry = QLineEdit()
        vbox.addWidget(self.port_entry)

        connect_button = QPushButton('접속')
        connect_button.clicked.connect(self.on_connect_click)
        vbox.addWidget(connect_button)

        self.setLayout(vbox)

    def on_connect_click(self):
        ip = self.ip_entry.text()
        port = int(self.port_entry.text())

        s = self.connect_to_chat(ip, port)
        if s is not None:
            self.chat_window = ChatWindow(s)
            self.chat_window.show()
            self.hide()

    def connect_to_chat(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((ip, port))
            return s
        except socket.error as e:
            QMessageBox.warning(self,f"{e}")
            return None

def main():
    app = QApplication(sys.argv)
    connect_window = ConnectWindow()
    connect_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

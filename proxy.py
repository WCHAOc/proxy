# -*- coding: utf-8 -*-

import select
import socket
import struct
import requests
import sys
import getpass
from socketserver import StreamRequestHandler as Tcp, ThreadingTCPServer
SOCKS_VERSION = 5  # socks版本
VERSION = 1.0

"""
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    一、客户端认证请求
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     |  1~255   |
        +----+----------+----------+
    二、服务端回应认证
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
    三、客户端连接请求(连接目的网络)
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    四、服务端回应连接
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
"""


# 无需认证类
class Proxy(Tcp):
    def handle(self):
        # noinspection PyGlobalUndefined
        global address, bind_address, remote
        print("客户端：", self.client_address, " 请求连接！")
        # 从客户端读取并解包两个字节的数据
        header = self.connection.recv(2)
        VER, NMETHODS = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert VER == SOCKS_VERSION, 'SOCKS版本错误'
        methods = self.IsAvailable(NMETHODS)
        # 检查是否支持该方式，不支持则断开连接
        if 0 not in set(methods):
            self.server.close_request(self.request)
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION, 'socks版本错误'
        if address_type == 1:       # IPv4
            # 转换IPV4地址字符串（xxx.xxx.xxx.xxx）成为32位打包的二进制格式（长度为4个字节的二进制字符串）
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:     # Domain
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)
        port = struct.unpack('!H', self.connection.recv(2))[0]
        # 响应，只支持CONNECT请求
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                print('已建立连接：', address, port)
            else:
                self.server.close_request(self.request)
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type, addr, port)
        except Exception as err:
            print(err)
            # 响应拒绝连接的错误
            reply = self.ReplyFaild(address_type, 5)
        self.connection.sendall(reply)      # 发送回复包

        # 建立连接成功，开始交换数据
        if reply[1] == 0 and cmd == 1:
            self.ExchangeData(self.connection, remote)
        self.server.close_request(self.request)

    def IsAvailable(self, n):
        """
        检查是否支持该验证方式
        """
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def ReplyFaild(self, address_type, error_number):
        """
        生成连接失败的回复包
        """
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def ExchangeData(self, client, remote):
        """
        交换数据
        """
        while True:
            # 等待数据
            rs, ws, es = select.select([client, remote], [], [])
            if client in rs:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break
            if remote in rs:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break


# 加入了认证模块
class AuthenticationProxy(Tcp):
    # 用户认证 用户名/密码
    username = ""
    password = ""

    def handle(self):
        print("客户端：", self.client_address, " 请求连接！")
        """
        一、客户端认证请求
            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     |  1~255   |
            +----+----------+----------+
        """
        # 从客户端读取并解包两个字节的数据
        header = self.connection.recv(2)
        VER, NMETHODS = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert VER == SOCKS_VERSION, 'SOCKS版本错误'

        # 接受支持的方法
        # 无需认证：0x00    用户名密码认证：0x02
        assert NMETHODS > 0
        methods = self.IsAvailable(NMETHODS)
        # 检查是否支持该方式，不支持则断开连接
        if 2 not in set(methods):
            self.server.close_request(self.request)
            return

        """
        二、服务端回应认证
            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+
        """
        # 发送协商响应数据包
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

        # 校验用户名和密码
        if not self.VerifyAuth():
            return

        """
        三、客户端连接请求(连接目的网络)
            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  |   1   |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION, 'socks版本错误'
        if address_type == 1:  # IPv4
            # 转换IPV4地址字符串（xxx.xxx.xxx.xxx）成为32位打包的二进制格式（长度为4个字节的二进制字符串）
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)
        port = struct.unpack('!H', self.connection.recv(2))[0]

        """
        四、服务端回应连接
            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  |   1   |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        # 响应，只支持CONNECT请求
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                print('已建立连接：', address, port)
            else:
                self.server.close_request(self.request)
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type, addr, port)
        except Exception as err:
            print(err)
            # 响应拒绝连接的错误
            reply = self.ReplyFaild(address_type, 5)
        self.connection.sendall(reply)  # 发送回复包

        # 建立连接成功，开始交换数据
        if reply[1] == 0 and cmd == 1:
            self.ExchangeData(self.connection, remote)
        self.server.close_request(self.request)

    def IsAvailable(self, n):
        """
        检查是否支持该验证方式
        """
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def VerifyAuth(self):
        """
        校验用户名和密码
        """
        version = ord(self.connection.recv(1))
        assert version == 1
        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')
        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')
        if username == self.username and password == self.password:
            # 验证成功, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True
        # 验证失败, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def ReplyFaild(self, address_type, error_number):
        """
        生成连接失败的回复包
        """
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def ExchangeData(self, client, remote):
        """
        交换数据
        """
        while True:
            # 等待数据
            rs, ws, es = select.select([client, remote], [], [])
            if client in rs:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break
            if remote in rs:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break


def run():
    if authentication:
        server = ThreadingTCPServer(('', port), AuthenticationProxy)
        print("**********************************************************")
        print("************************ PROXY ***************************")
        print(f"                   EIP:{ip1}")
        print(f"                   IIP:{ip2}")
        print(f"                   PORT:{port}")
        print(f"                   USER:{AuthenticationProxy.username}")
        print(f"                   PASSWORD:{AuthenticationProxy.password}")
        print("**********************************************************")
        server.serve_forever()
    else:
        server = ThreadingTCPServer(('', port), Proxy)
        print("**********************************************************")
        print("************************ PROXY ***************************")
        print(f"                   EIP:{ip1}")
        print(f"                   IIP:{ip2}")
        print(f"                   PORT:{port}")
        print("**********************************************************")
        server.serve_forever()


try:
    if __name__ == '__main__':
        port = 8888
        try:
            # 服务器上创建一个TCP多线程服务
            ip1 = requests.get("https://ipconfig.io/ip", timeout=8).text.strip()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip2 = s.getsockname()[0]
            s.close()
            path = sys.argv
            if len(path) == 1:
                print("-----------------------------------------------------")
                print(" ---------------------- PROXY ----------------------")
                print(" ---------------------- By @Chao -------------------")
                print("                run,直接启动代理服务器")
                print("                -p,指定代理服务器端口")
                print("                -a,加上用户名密码认证")
                print("                -v,查看版本等信息")
                print("                .eg")
                print("                proxy run;proxy -p 5432;\n"
                      "                proxy run -a;proxy -a -p 5432;")
                print("-----------------------------------------------------")
            else:
                authentication = False
                PORT = False
                for i in path:
                    if i == "-a":
                        authentication = True
                    elif i == "-p":
                        PORT = True
                    elif i == "-v":
                        exit("PROXY BY @Chao\n"
                             f"version:{VERSION}"
                             )
                if authentication is False and PORT is False:
                    run()
                elif authentication is True and PORT is False:
                    AuthenticationProxy.username = str(input("username:"))
                    AuthenticationProxy.password = str(getpass.getpass("password:"))
                    run()
                elif authentication is False and PORT is True:
                    port = int(sys.argv[sys.argv.index("-p") + 1])
                    run()
                elif authentication is True and PORT is True:
                    AuthenticationProxy.username = str(input("username:"))
                    AuthenticationProxy.password = str(getpass.getpass("password:"))
                    port = int(sys.argv[sys.argv.index("-p") + 1])
                    run()
        except OSError:
            print(f"端口 \"{port}\" 被占用")
        except KeyboardInterrupt:
            exit("")
except KeyboardInterrupt:
    exit("")
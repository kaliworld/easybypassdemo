import socket
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import sys

def tcp_con(sleep=bool):
     # 创建一个TCP/IP套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 绑定到指定端口
    server_address = ('0.0.0.0', 9999)
    print('Starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)
    
    # 开始监听连接
    sock.listen(1)
    
    print('Waiting for a connection...')
    connection, client_address = sock.accept()
    print('Connection from', client_address)

    connection.close()
    #反沙箱睡眠200秒，后面开启http服务 
    if(sleep):
        print('ok , tcp done and will go to sleep')
        time.sleep(200)
        print('ok , sleep done')
    
    return 0

def serve_file(file_path, n=5, port=8000):
    class FileRequestHandler(BaseHTTPRequestHandler):
        request_count = 0  # 用于追踪请求数量

        def do_GET(self):
            # 设置响应头
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            # 读取文件内容并发送给客户端
            with open(file_path, 'rb') as file:
                self.wfile.write(file.read())
            
            # 每次请求计数加一
            FileRequestHandler.request_count += 1

            # 如果请求数量超过指定数量，关闭HTTP服务器
            if FileRequestHandler.request_count >= n:
                print("Reached maximum request count. Shutting down the server...")
                #self.server.shutdown()
                sys.exit(0)
                

    # 启动HTTP服务器
    server_address = ('', port)
    httpd = HTTPServer(server_address, FileRequestHandler)
    print(f'Starting httpd on port {port}...')
    
    
    # 开始监听并处理请求
    httpd.serve_forever()


def main():
    #tcp_con()
    #print("sleep end, start real server")
    tcp_thread1 = threading.Thread(target=serve_file, args=('test.txt',))
    tcp_thread1.start()

    # 创建第二个线程，运行 tcp_con 函数
    tcp_thread2 = threading.Thread(target=tcp_con, args=(True,))
    tcp_thread2.start()

    tcp_thread2.join()
    tcp_con(False)
    # 等待两个线程完成
    sum = 0
    while True:
        sum = sum + 1
        if sum > 10:
            break
        tcp_thread = threading.Thread(target=tcp_con, args=(True,))
        tcp_thread.start()
        tcp_thread.join()
        tcp_con(False)

    tcp_thread1.join()
    
    # 当线程都完成后，继续执行下一步
    print('this code never be come, beacase the thread will end ')



if __name__ == '__main__':
    main()


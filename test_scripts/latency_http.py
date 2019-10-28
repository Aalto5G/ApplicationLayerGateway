import socket
import time

#sock_list = []

for n in range(1000):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  s.connect(('test.gwa.demo', 80))
  s.send(b'GET / HTTP/1.1\r\nHost: test.gwa.demo\r\n\r\n')
  #sock_list.append(s)
  print(len(s.recv(1024)))
  s.close()

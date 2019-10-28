import random
import socket
import time
import datetime

conn= []
n=100
m= 1
while m <= 1000:
    for l in range(n,201,1):
        conn.append(l)
    m +=1

ip= []
sock_list= []
count= 0
ports= list(range(1024,65536))
random.shuffle(ports)

for item in conn:
    a= str(item)
    b = '100.64.0.'
    ip.append(b+a)

for n in range(10):
    k = ports[n]
    sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((ip[n], k))
    sock.connect(('100.64.1.130',80))
    print('Time when initiating the connection\n', datetime.datetime.now())

    #Senidng an empty byte instead of the GET request to establsih the connection
    sock.send(b'')
    data=sock.recv(1024)
    print('Time when socket closed\n', datetime.datetime.now())
    sock.close()
    print('Received', data)
    sock_list.append(sock)
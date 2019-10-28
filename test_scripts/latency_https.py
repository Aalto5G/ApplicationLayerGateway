"""
BSD 3-Clause License

Copyright (c) 2019, Maria Riaz, Aalto University, Finland
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


#This script is used for measuring the latency of HTTPS connection by sending serial HTTPS requests

import socket
import ssl
import time
import random

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

#specify the hostname of the target web server
hostname = 'www.test.gwa.demo'
context = ssl._create_unverified_context()

conn= []
n=100
m= 1
temp='100.64.0.'
while m <= 10:
    for l in range(n,200,1):
        #specify the IP addresses of the public clients in list 'conn'
        conn.append(temp+str(l))
    m +=1


count= 0
ports= list(range(1024,65536))
random.shuffle(ports)

for n in range(1010):
    k = ports[n]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind((conn[n], k))
    sock.connect((socket.gethostbyname(hostname), 443))
    ssock=context.wrap_socket(sock, server_hostname=hostname)
    #print(ssock.version())
    ssock.send(b'GET / HTTP/1.1\r\nHost: www.test.gwa.demo\r\n\r\n')
    ssock.recv(1024)
    ssock.close()
    sock.close()

print(time.process_time())
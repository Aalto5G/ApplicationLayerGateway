#!/usr/bin/python3

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

import socket
import sys
import os
import errno
import yaml
import select
import httpparser
import sslparser
import pwd, grp
import datetime
import posix_ipc
import time
import traceback
import signal
import argparse


def drop_privileges(uid_name, gid_name):
    if os.getuid() != 0:
        # Not running as root
        print("Not running as root. Cannot drop permissions.")
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

def open_listening_sockets(port):

    # Return a listening server socket for ipv6
    sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

    # Bind to the public IP address on which ALG runs
    sock6.bind(('::', port))

    #Specify the maximum backlog size for the tcp_syn packets in linux
    sock6.listen(20000)

    # Return a listening server socket for ipv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #Bind to the public IP address on which ALG runs
    sock.bind(('0.0.0.0', port))

    # Specify the maximum backlog size for the tcp_syn packets in linux
    sock.listen(20000)

    return sock6, sock


def open_connected_socket(remote_host, remote_port):
    if ':' in remote_host:
        remote_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        remote_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        remote_socket.connect((remote_host, remote_port, 0, 0))

    else:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        remote_socket.connect((remote_host, remote_port))

    remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    remote_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5 * 60)
    return remote_socket


def copy_data_from_to_until_read_returns_zero(s1, s2):
    buf_size = 4096

    while True:
        data = s1.recv(buf_size)
        # print(data)

        if len(data) == 0:
            return

        else:
            s2.send(data)
            log_string = "{} sent data to {}:_loglevel_0".format(s1.getpeername(), s2.getpeername())
            logging_data(log_string, sem, LOG_FILENAME)


def extracting_hostname(s):
    buffer_len = 8192
    amount_rcvd = 0

    timeout_wait = datetime.timedelta(seconds=timeout_hostname)
    data_block = []
    data = ""
    host = None
    temp_buf = 1
    first_byte = b''
    control_byte = b'\x16'
    initial_time = datetime.datetime.now()

    while datetime.datetime.now() < (initial_time + timeout_wait):
        try:
            first_byte = s.recv(temp_buf, socket.MSG_PEEK)
            break

        except socket.timeout:
            pass

    if first_byte == b'':
        log_string = "[Connection-ID {}] Remote host {} did not send any data and connection timed out::_loglevel_3".format(
            connection_count, s.getpeername())
        logging_data(log_string, sem, LOG_FILENAME)
        sys.exit()

    if first_byte == control_byte:
        ctx = sslparser.Ssl()
        proto = 'HTTPS'

    else:
        ctx = httpparser.Http()
        proto = 'HTTP'

    while amount_rcvd <= buffer_len and datetime.datetime.now() < (initial_time + timeout_wait):

        try:
            data = s.recv(buffer_len)

        except socket.timeout:
            data = b''

        amount_rcvd += len(data)
        data_block.append(data)
        a = ctx.feed(data, 0)

        if a == -errno.EPIPE:
            host = ctx.host()
            if host is not None:
                host = host.split(":")[0]
                break

        elif a != -errno.EAGAIN:
            log_string = "[Connection-ID {}] Cannot find the requested host. Connection timed out:_loglevel_3".format(
                connection_count)
            logging_data(log_string, sem, LOG_FILENAME)

            sys.exit()

    if host is None:
        log_string = "[Connection-ID {}] Cannot find the requested host. Connection timed out:_loglevel_3".format(
            connection_count)
        logging_data(log_string, sem, LOG_FILENAME)
        sys.exit()

    buf = b''.join(data_block)

    return host, buf, proto


def hostname_to_ip(host, port, table):
    tuple_2 = host + ':' + str(port)

    if tuple_2 not in table:
        log_string = "[Connection-ID {}] {} is not specified in ALG's record:_loglevel_2".format(connection_count, tuple_2)
        logging_data(log_string, sem, LOG_FILENAME)


    else:
        ip_addr = table[tuple_2]['addr']
        connecting_port = table[tuple_2]['port']
        return ip_addr, connecting_port



def loading_config(filename):
    if not filename:
        log_string = "Configuration file not specified :_loglevel_3"
        logging_data(log_string, sem, LOG_FILENAME)

    config_settings = {}

    try:
        fileDir = os.path.dirname(os.path.abspath(__file__))
        file_name = os.path.join(fileDir, '../config.d/{}'.format(filename))
        file_name = os.path.abspath(os.path.realpath(file_name))
        config_settings = yaml.safe_load(open(file_name, 'r'))

    except FileNotFoundError:
        log_string = 'Repository file not found {filename} :_loglevel_3'.format(filename=filename)
        logging_data(log_string, sem, LOG_FILENAME)

    except yaml.YAMLError as exc:
        log_string = 'Error parsing file {filename}: {exc}. Please fix and try again. :_loglevel_3'.format(
            filename=filename, exc=exc)
    finally:
        return config_settings


def return_accepted_connection(conn_dict):
    read, write, error = select.select(conn_dict, [], [], 1)

    for r in read:
        for item in conn_dict:
            if r == item:
                socket_new, address = item.accept()
                return socket_new


def custom_formatter():
    time_string = datetime.datetime.now().strftime("%d %B %Y %I:%M:%S %p")
    return time_string


def logging_data(data_stream, sem, filename):
    global f
    global LOG_LEVEL
    global file_size

    log_console = {0: 'DEBUG', 1: 'INFO', 2: 'WARNING', 3: 'ERROR'}

    stream_check = data_stream.split(':_loglevel_')

    level = int(stream_check[1])

    if level < LOG_LEVEL:
        return

    elif level >= LOG_LEVEL:
        sem.acquire()
        try:
            if os.fstat(f).st_size > file_size:
                os.close(f)
                f = os.open(filename, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o666)

                if os.fstat(f).st_size > file_size:
                    os.close(f)
                    os.rename(filename, '.'.join([filename, "old"]))
                    f = os.open(filename, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o666)

            time_append = custom_formatter()
            data_stream = stream_check[0]
            formatted_string = (
                        time_append + ' ' + '-' + ' ' + log_console[LOG_LEVEL] + ' ' + '-' + ' ' + data_stream + "\n")
            os.write(f, bytes(formatted_string, "utf-8"))

        finally:
            sem.release()


def socket_decorator(sock, count):
    PROTOCOL = sock.proto
    tuple_remote = sock.getpeername()
    remote_addr = tuple_remote[0]

    if PROTOCOL == 0:
        PROTOCOL = 'TCP'

    if '.' in remote_addr:
        IP_LAYER = 'IPv4'
        local_addr, local_port = sock.getsockname()
        remote_addr, remote_port = sock.getpeername()

    elif ':' in remote_addr:
        IP_LAYER = 'IPv6'
        local_addr, local_port, flow_info, scope_id = sock.getsockname()
        remote_addr, remote_port, flow_info, scope_id = sock.getpeername()

    sock_information = "[Connection-ID {}] A new {} connection is initiated by a remote {} host {} using port {} on " \
                       "local address {} and local port {}".format(count, PROTOCOL, IP_LAYER, remote_addr, remote_port,
                                                                   local_addr, local_port)

    return sock_information


def rate_limiting(max_tokens, fill_rate, last_fill, current_tokens):
    if datetime.datetime.now() > last_fill + datetime.timedelta(seconds=1):
        diff = int((datetime.datetime.now() - last_fill).total_seconds())
        tokens = current_tokens + (fill_rate * diff)
        final_tokens = min(max_tokens, tokens)
        last_fill = last_fill + diff * datetime.timedelta(seconds=1)
        return final_tokens, last_fill

    else:

        return current_tokens, last_fill


def updating_policies(current):
    global last_call
    global initialization_time
    global load_file
    global config_file
    global map_table

    if datetime.datetime.now() - last_call < datetime.timedelta(seconds=10):

        return

    else:
        fileDir = os.path.dirname(os.path.abspath(__file__))
        file_name = os.path.join(fileDir, '../config.d/{}'.format(config_file))
        file_name = os.path.abspath(os.path.realpath(file_name))

        temp = os.stat(file_name).st_mtime
        if temp != initialization_time:
            load_file = loading_config(config_file)
            map_table = load_file['HOSTNAME_TO_IP_LOOKUP_TABLE']

            initialization_time = temp

    last_call = datetime.datetime.now()


if __name__ == '__main__':

    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    connections = []
    connection_count = 0

    #Adjust the values of max_tokens and current_tokens for the token-bucket algorithm
    max_tokens = 40000
    current_tokens = 40000
    fill_rate = 500

    initialization_time = None
    last_call = datetime.datetime.now()
    last_fill = datetime.datetime.now()

    config_file = 'config.yml'
    default_user='root'
    default_group = 'root'

    parser = argparse.ArgumentParser()
    parser.add_argument("-config_file", type=str, help="Specify the name of the configuration file (default={})".format(config_file), default=config_file)
    parser.add_argument("-user", type=str, help="Specify the user running the ALG (default={})".format(default_user), default= default_user)
    parser.add_argument("-group", type=str, help="Specify the group id of the user (default={})".format(default_group), default=default_group)
    args = parser.parse_args()

    config_file = args.config_file
    load_file = loading_config(config_file)
    log_file = load_file['Log']['log_filename']
    level_log = load_file['Log']['log_level']

    LOG_FILENAME = log_file
    Dir_LOG = os.path.dirname(os.path.abspath(__file__))
    file_name = os.path.join(Dir_LOG, '../{}'.format(LOG_FILENAME))
    file_name = os.path.abspath(os.path.realpath(file_name))
    LOG_FILENAME = file_name
    print(LOG_FILENAME)
    LOG_LEVEL = level_log


    sem = posix_ipc.Semaphore(None, posix_ipc.O_CREX, initial_value=1)

    try:
        list_ports = load_file['Ports']
        map_table = load_file['HOSTNAME_TO_IP_LOOKUP_TABLE']
        uid_name = args.user
        gid_name = args.group
        file_size = load_file['Log']['log_filesize']
        timeout_socket = load_file['Timeout']['Socket_Tiemout']
        timeout_hostname = load_file['Timeout']['Connection_Timeout']

        for ports in list_ports:
            new_conn, new_ipv6 = open_listening_sockets(ports)
            connections.append(new_conn)
            connections.append(new_ipv6)

        drop_privileges(uid_name, gid_name)

        current_user = pwd.getpwuid(os.getuid())[0]
        current_group = grp.getgrgid(os.getgid())[0]

        f = os.open(LOG_FILENAME, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o666)

        log_string = "Starting Application Layer Gateway and Loading Configuration file '{}':_loglevel_1".format(config_file)
        logging_data(log_string, sem, LOG_FILENAME)

        current_user = pwd.getpwuid(os.getuid())[0]
        current_group = grp.getgrgid(os.getgid())[0]

        log_string = "Logging the user credentials; User is {} and Group is {} :_loglevel_1".format(current_user,current_group)
        logging_data(log_string, sem, LOG_FILENAME)

        # Wait for any of the listening servers to get a client connection attempt
        while True:

            socket1 = return_accepted_connection(connections)

            time_current = datetime.datetime.now()

            updating_policies(time_current)

            if socket1 is None:
                continue

            socket1.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            socket1.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5 * 60)

            current_tokens, last_fill = rate_limiting(max_tokens, fill_rate, last_fill, current_tokens)

            if current_tokens == 0:
                socket1.close()
                log_string = "Cannot accept any new connections :_loglevel_3"
                logging_data(log_string, sem, LOG_FILENAME)
                continue

            current_tokens -= 1

            connection_count += 1
            data_string = socket_decorator(socket1, connection_count)
            log_string = ':_loglevel_'.join([data_string, '1'])

            logging_data(log_string, sem, LOG_FILENAME)

            # setting a timeout to avoid blocking by the receiving socket
            socket1.settimeout(timeout_socket)

            in_addr = socket1.getsockname()
            in_port = in_addr[1]

            try:

                if os.fork() == 0:

                    for connection in connections:
                        connection.close()

                    hostname, buffer, proto = extracting_hostname(socket1)
                    socket1.settimeout(None)
                    log_string = "[Connection-ID {}] '{}': '{} trying to connect to host '{}' using  {} :_loglevel_1".format(
                        connection_count, in_addr[0], in_addr[1], hostname, proto)
                    logging_data(log_string, sem, LOG_FILENAME)

                    # Specify the input port to tell which service to be used if server supports multiple services
                    IP, conn_port = hostname_to_ip(hostname, in_port, map_table)
                    data_string = "[Connection-ID {}] {} is running at {} address and port {} ".format(connection_count,
                                                                                                       hostname, IP,
                                                                                                       conn_port)
                    log_string = ':_loglevel_'.join([data_string, '1'])
                    logging_data(log_string, sem, LOG_FILENAME)

                    socket2 = open_connected_socket(IP, conn_port)

                    data_string = socket_decorator(socket2, connection_count)
                    log_string = ':_loglevel_'.join([data_string, '1'])
                    logging_data(log_string, sem, LOG_FILENAME)

                    remote_pair = socket1.getpeername()

                    socket2.send(buffer)


                    #forking a child process to accept incoming connectons in another process
                    try:

                        pid = os.fork()
                        if pid == 0:
                            try:

                                remote_pair = socket1.getpeername()

                                copy_data_from_to_until_read_returns_zero(socket1, socket2)
                                log_string = "[Connection-ID {}] {} is closing the connection and cannot send any more data :_loglevel_2".format(
                                    connection_count, remote_pair)
                                logging_data(log_string, sem, LOG_FILENAME)

                                socket2.shutdown(socket.SHUT_WR)

                            except OSError:
                                log_string = "[Connection-ID {}] Client has already closed the connection :_loglevel_3".format(
                                    connection_count)
                                logging_data(log_string, sem, LOG_FILENAME)

                                socket2.shutdown(socket.SHUT_WR)

                            finally:
                                try:
                                    socket2.shutdown(socket.SHUT_WR)

                                finally:
                                    log_string = "[Connection-ID {}] Time {}:_loglevel_2".format(connection_count,
                                                                                             time.clock())
                                    #logging_data(log_string, sem, LOG_FILENAME)
                                    sys.exit(1)

                        elif pid > 0:
                            try:
                                master_pair = socket2.getpeername()

                                copy_data_from_to_until_read_returns_zero(socket2, socket1)
                                log_string = "[Connection-ID {}] {} is closing the connection and cannot send any more data :_loglevel_2".format(
                                    connection_count, master_pair)
                                logging_data(log_string, sem, LOG_FILENAME)
                                socket1.shutdown(socket.SHUT_WR)


                            except OSError:
                                log_string = "[Connection-ID {}] The Server has already closed the connection :_loglevel_3".format(
                                    connection_count)
                                logging_data(log_string, sem, LOG_FILENAME)
                                socket1.shutdown(socket.SHUT_WR)

                            finally:
                                try:
                                    socket1.shutdown(socket.SHUT_WR)

                                finally:
                                    log_string = "[Connection-ID {}] Time {}:_loglevel_2".format(connection_count,
                                                                                             time.clock())
                                    #logging_data(log_string, sem, LOG_FILENAME)
                                    sys.exit(1)


                        else:
                            # fork failed
                            log_string = "[Connection-ID {}] Unable to open a new process for {}:_loglevel_3".format(
                                connection_count, socket2.getpeername())
                            logging_data(log_string, sem, LOG_FILENAME)

                            sys.exit(1)

                    except OSError as e:
                        try:
                            log_string = "[Connection-ID {}] {}:_loglevel_3".format(connection_count,
                                                                                traceback.format_tb(sys.exc_info()[2]))
                            logging_data(log_string, sem, LOG_FILENAME)
                        finally:
                            sys.exit(1)

                    except KeyboardInterrupt:
                        sys.exit(1)

                else:

                    try:
                        # closing the socket in the master process, the child process still has it open, if the fork didn’t fail
                        log_string = "[Connection-ID {}] Closing  the connection from {} in the main process and running it in the background :_loglevel_1".format(
                            connection_count, socket1.getpeername())
                        logging_data(log_string, sem, LOG_FILENAME)

                    except OSError:
                        log_string = "[Connection-ID {}] The other end has already closed the connection :_loglevel_3".format(
                            connection_count)
                        logging_data(log_string, sem, LOG_FILENAME)

                    socket1.close()

            except OSError as e:
                try:
                    log_string = "[Connection-ID {}] {}:_loglevel_3".format(connection_count,
                                                                        traceback.format_tb(sys.exc_info()[2]))
                    logging_data(log_string, sem, LOG_FILENAME)
                    socket1.shutdown(socket.SHUT_WR)
                    socket1.close()

                finally:
                    sys.exit(1)



    except KeyboardInterrupt:

        log_string = "Interrupted by user, exiting:_loglevel_3"
        logging_data(log_string, sem, LOG_FILENAME)

    log_string = "Shutting down ALG:_loglevel_1"
    logging_data(log_string, sem, LOG_FILENAME)
    sys.exit(0)

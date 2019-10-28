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

import asyncio
import aiohttp
import yaml
import json
import datetime
import os


class HTTPRestClient(object):

    def __init__(self, limit):

        # Initializing HTTP client object
        conn = aiohttp.TCPConnector(limit=limit)
        self.session = aiohttp.ClientSession(connector=conn)

    def close(self):
        self.session.close()

    @asyncio.coroutine
    def do_get(self, url, params=None, timeout=None):
        with aiohttp.Timeout(timeout):
            resp = yield from self.session.get(url, params=params)
            try:
                # Any actions that may lead to error:
                return (yield from resp.text())
            except Exception as e:
                # .close() on exception.
                resp.close()
                raise e
            finally:
                # .release() otherwise to return connection into free connection pool.
                # It's ok to release closed response:
                # https://github.com/KeepSafe/aiohttp/blob/master/aiohttp/client_reqrep.py#L664
                yield from resp.release()


@asyncio.coroutine
def get_policies():
    while True:

        # Poll the database after 2 seconds
        yield from asyncio.sleep(2)
        new_client = HTTPRestClient(5)

        dictionary = {'policy_name': 'ALG'}

        #Specify the IP address and port on which the policy_api server is running
        fetch_policy = yield from new_client.do_get('http://127.0.0.1:8000/API/bootstrap_policies_ces',
                                                    params=dictionary, timeout=None)
        fetch_policy = json.loads(fetch_policy)


        for key in fetch_policy:
            if key == 'ALG':
                data = fetch_policy[key]
                fileDir = os.path.dirname(os.path.realpath('__file__'))
                file_name = os.path.join(fileDir, '../config.d/config.yml')
                file_name = os.path.abspath(os.path.realpath(file_name))

               #Default path for the configuration file
                if os.path.isfile(file_name):

                    f1 = yaml.safe_load(open(file_name, 'r'))
                    map_table = f1['HOSTNAME_TO_IP_LOOKUP_TABLE']

                    if map_table == data['HOSTNAME_TO_IP_LOOKUP_TABLE']:

                        pass

                    else:
                        with open('dump.yml', 'w') as yml:
                            yaml.dump(data, yml, allow_unicode=False)

                        os.rename('dump.yml', file_name)



                else:
                    with open('temp.yml', 'w') as yml:
                        yaml.dump(data, yml, allow_unicode=False)

                    os.rename('temp.yml', file_name)

        new_client.close()


if __name__ == '__main__':

    try:
        loop = asyncio.get_event_loop()
        # loop.run_forever(loop.create_task(get_policies()))
        loop.run_until_complete(loop.create_task(get_policies()))

    except KeyboardInterrupt:
        print('\nInterrupted\n')
    finally:
        # next two lines are required for actual aiohttp resource cleanup
        loop.stop()
        # loop.run_forever()
        loop.close()



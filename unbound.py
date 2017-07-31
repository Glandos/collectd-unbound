#! /usr/bin/python
# Copyright 2014 Tom Arnfeld
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import ssl
import socket
import subprocess

from contextlib import closing

try:
    import collectd
except:
    collectd = None

CHECKCONF_CMD = '/usr/sbin/unbound-checkconf'
VERBOSE_LOGGING = False
CONFIGURATION = {
        'host': None,
        'port': None,
        'key_file': None,
        'cert_file': None,
        'ca_certs': None,
        'ssl_context': None,
        '_is_init': False,
        }


class FakeConf:
    children = []


def get_conf_value(value):
    try:
        output = subprocess.check_output([CHECKCONF_CMD, '-o', value], stderr=subprocess.STDOUT)
        return output.strip()
    except subprocess.CalledProcessError as e:
        message = 'unbound plugin in configuration: {}: {}'.format(e.returncode, e.output)
        if collectd:
            collectd.error(message)
        else:
            print(message)


def configure_callback(conf):
    """Received configuration information"""

    global CHECKCONF_CMD, VERBOSE_LOGGING
    for node in conf.children:
        if node.key == 'CheckconfCmd':
            CHECKCONF_CMD = node.values[0].split(" ")
        elif node.key == 'Verbose':
            VERBOSE_LOGGING = bool(node.values[0])
        else:
            collectd.warning('unbound plugin: Unknown config key: %s.' % node.key)

    if not get_conf_value('control-enable') == 'yes':
        return
    CONFIGURATION['key_file'] = get_conf_value('control-key-file')
    CONFIGURATION['cert_file'] = get_conf_value('control-cert-file')
    CONFIGURATION['ca_certs'] = get_conf_value('server-cert-file')
    CONFIGURATION['port'] = int(get_conf_value('control-port'))
    interface = get_conf_value('control-interface')

    # See https://github.com/NLnetLabs/unbound/blob/abb6cfdebdbfea2a17c3b3044f67ed57024a21e0/smallapp/unbound-control.c#L480
    if not interface:
        interface = '127.0.0.1' if get_conf_value('do-ip4') == 'yes' else '::1'
    elif interface == '0.0.0.0':
        interface = '127.0.0.1'
    elif interface in ['::0', '0::0', '0::', '::']:
        interface = '::1'
    CONFIGURATION['host'] = interface

    context = ssl.create_default_context(cafile=CONFIGURATION['ca_certs'])
    context.load_cert_chain(CONFIGURATION['cert_file'], CONFIGURATION['key_file'])
    context.check_hostname = False
    CONFIGURATION['ssl_context'] = context

    CONFIGURATION['_is_init'] = True
    log_verbose('Configuration done with {}'.format(CONFIGURATION))


def fetch_stats():
    with closing(CONFIGURATION['ssl_context'].wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=CONFIGURATION['host'])) as s:
        s.connect((CONFIGURATION['host'], CONFIGURATION['port']))
        s.write('UBCT1 stats\n')
        for line in s.makefile():
            yield line.split('=')

            
def dispatch_stat(key, value):
    val = collectd.Values(plugin='unbound')
    val.type = "gauge"
    val.type_instance = key.replace(".", "/")
    val.values = [value]
    val.dispatch()

    
def read_callback():
    log_verbose('Read callback called')
    if not CONFIGURATION['_is_init']:
        configure_callback(FakeConf)

    stats = fetch_stats()
    for key, value in stats:
        dispatch_stat(key, value)

        
def log_verbose(msg):
    if not VERBOSE_LOGGING:
        return
    collectd.info('unbound plugin [verbose]: %s' % msg)

if collectd:
    collectd.register_config(configure_callback)
    collectd.register_read(read_callback)


if __name__ == '__main__':
    configure_callback(FakeConf)
    for key, value in fetch_stats():
        print('{}: {}'.format(key, value), end="")
        

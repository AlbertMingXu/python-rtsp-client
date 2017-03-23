#!/usr/bin/env python3
#-*-coding:utf-8-*-

import socket
import select
import urllib.parse
import sys
import logging
import os
import re
import time
import struct
import threading
from argparse import ArgumentParser

TRANSPORT_TYPE      = ''
DEST_IP             = socket.gethostbyname(socket.gethostname())
CLIENT_PORT_RANGE   = '10014-10015'
NAT_IP_PORT         = ''
ENABLE_ARQ          = False
ENABLE_FEC          = False

TRANSPORT_TYPE_MAP  = { 'ts_over_tcp'  : 'MP2T/TCP;%s;interleaved=0-1',
                        'ts_over_udp'  : 'MP2T/UDP;%s;destination=%s;client_port=%s'
                      }

RTSP_VERSION        = 'RTSP/1.0'
RTSP_STATUS_CODE    = [200, 302]
DEFAULT_USERAGENT   = 'Python RTSP Client 1.0'
HEARTBEAT_INTERVAL  = 10

LINE_SPLIT_STR      = '\r\n'
HEADER_END_STR      = LINE_SPLIT_STR*2

CUR_RANGE           = 'npt=0-'
CUR_SCALE           = 1

DURATION            = 0
UDP_TIMEOUT_NUM     = 3

UDP_BIND_ERR, TCP_CONNECT_ERR, RTSP_RESP_ERR, RTSP_ANNOUNCE_ERR, SOCK_ERR = 201, 202, 203, 204, 205

logging.basicConfig(filename=None,level=logging.INFO,format='[%(asctime)s] %(levelname)s %(filename)s %(funcName)s %(lineno)s:%(message)s')

class RTSPClient:
    def  __init__(self, url, dst_ip=None, port=12345, filehandle=None, duration=0):
        self._url = url
        self.dst_ip = dst_ip
        self.dst_port = port
        self.sock = None
        self.udpsock = None
        self.filehandle = filehandle
        self.bytes = 0
        self._cseq = 1
        self._cseq_map  = dict()
        self.encoding = 'latin-1'
        self._shutdown = False
        self._time = None
        self._play_time = None
        self._buffer_size = 65535
        self._func = None
        self._session_id = None
        self._duration = duration
        self._retval = 0
        if TRANSPORT_TYPE.endswith('udp'):
            self.udp_sock_bind(self.dst_ip, int(self.dst_port.split('-')[0]))

    def udp_sock_bind(self, host, port):
        try:
            if self.udpsock: return
            self.udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udpsock.bind((host, port))
        except Exception as e:
            logging.error(e)
            sys.exit(UDP_BIND_ERR)
        logging.debug('udp binding %s:%s success.' % (host, port))

    def _connect_server(self):
        host, port = self.get_host_port()
        try:
            if self.sock:
                self.sock.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, int(port)))
        except Exception as e:
            logging.error(e)
            sys.exit(TCP_CONNECT_ERR)
        logging.debug('connect to %s:%s success.' %(host, port))

    def get_host_port(self):
        parse = urllib.parse.urlparse(self._url)
        if ':' in parse.netloc:
            return parse.netloc.split(':')
        else:
            return [parse.netloc,'80']

    def _next_cseq(self):
        self._cseq += 1
        return self._cseq

    def _get_transport_type(self):
        '''获取SETUP时需要的Transport字符串参数'''
        transport_str = ''
        ip_type = 'unicast'

        if TRANSPORT_TYPE.endswith('tcp'):
            transport_str = TRANSPORT_TYPE_MAP[TRANSPORT_TYPE] % ip_type
            self._func = self.wait_data_tcp
        else:
            transport_str = TRANSPORT_TYPE_MAP[TRANSPORT_TYPE] % (ip_type, DEST_IP, CLIENT_PORT_RANGE)
            self._func = self.wait_data_udp
        return transport_str

    def parse_response(self, msg):
        '''解析响应消息'''
        logging.info(' S -> C\n%s' % msg.strip())
        header, body = msg.split(HEADER_END_STR, 1)
        response, header_lines = header.split(LINE_SPLIT_STR, 1)
        headers = self.parse_header_params(header_lines.split(LINE_SPLIT_STR))
        protocol_version, code, message = re.match(r'^(.*)\s(\d+)\s(.*)$', response).groups()
        code = int(code)
        if code in RTSP_STATUS_CODE:
            del self._cseq_map[headers.get('cseq')]
        else :
            logging.error('%s ERROR, resp code is %s, message is "%s"' % (self._cseq_map.get(headers.get('cseq')), code, message))
            self.shutdown()
            self._retval = RTSP_RESP_ERR
        return code, message, headers, body

    def parse_announce(self, msg):
        '''处理ANNOUNCE通知消息'''
        msg = msg.split(HEADER_END_STR)[0]
        logging.info(' S -> C\n%s' % msg.strip())
        response, header_lines = msg.split(LINE_SPLIT_STR, 1)
        headers = self.parse_header_params(header_lines.split(LINE_SPLIT_STR))
        command, protocol_version = re.match(r'^(\w+)\s\*\s(.*)$', response).groups()
        if headers.get('x-reason', None) != '"END"':
            logging.error('ANNOUNCE MESSAGE %s ERROR, x-reason is "%s"' % (command, headers['x-reason']))
            self.shutdown()
            self.close()
            sys.exit(RTSP_ANNOUNCE_ERR)
        return command, headers

    def parse_header_params(self, header_param_lines):
        '''解析头部参数'''
        headers = dict()
        for line in header_param_lines:
            if line.strip(): # 跳过空行
                key,val = line.split(':', 1)
                headers[key.lower()] = val.strip()
        return headers

    def send_heart_beat_msg(self):
        '''定时发送OPTIONS消息保活'''
        if self._shutdown is False:
            self.do_options()
            self._heartbeat = threading.Timer(HEARTBEAT_INTERVAL, self.send_heart_beat_msg)
            self._heartbeat.start()

    def sendmsg(self, method, url, headers):
        '''发送消息'''
        if headers.get('User-Agent'):
            headers['User-Agent'] = DEFAULT_USERAGENT
        if self._session_id: headers['Session'] = self._session_id

        _buffer= []
        _buffer.append('%s %s %s' % (method, url, RTSP_VERSION))

        for keyword, value in headers.items():
            _buffer.append('%s: %s' % (keyword, value))

        msg  = LINE_SPLIT_STR.join(_buffer)
        msg += HEADER_END_STR
        self._cseq_map[str(headers.get('CSeq'))] = method

        try:
            self.sock.sendall(msg.encode(self.encoding))
            logging.info(' C -> S\n%s' % msg.strip())
        except socket.error as e:
            logging.error('send msg error: %s' % e)
            sys.exit(SOCK_ERR)

    def do_describe(self):
        headers = dict()
        headers['Accept'] = 'application/sdp'
        headers['User-Agent'] = DEFAULT_USERAGENT
        while True:
            headers['CSeq'] = self._cseq
            self._connect_server()
            self.sendmsg('DESCRIBE', self._url, headers)
            data = self.sock.recv(self._buffer_size).decode(self.encoding)
            if data.startswith(RTSP_VERSION):
                code, message, headers, body = self.parse_response(data)
                if code == 302:
                    self._url = headers.get('location')
                    logging.info('redirect %s' % self._url)
                elif code == 200:
                    parser_result = urllib.parse.urlparse(self._url)
                    self._url = urllib.parse.urlunparse((parser_result.scheme, parser_result.netloc, parser_result.path, '', '', ''))
                    break
            else:
                self.parse_announce(data)
                break

    def do_setup(self, track_id=0):
        if self._shutdown is True: return

        headers = dict()
        headers['User-Agent'] = DEFAULT_USERAGENT
        headers['CSeq'] = self._next_cseq()
        headers['Transport'] = self._get_transport_type()

        url = '%s/trackID=%s' % (self._url, track_id)
        self.sendmsg('SETUP', '%s' % url, headers)
        data = self.sock.recv(self._buffer_size).decode(self.encoding)
        code, message, headers, body = self.parse_response(data)
        if headers.get('session', None) is not None:
            self._session_id = headers['session']
    
    def do_play(self, range='npt=0-', scale='1.0'):
        if self._shutdown is True: return

        headers = dict()
        headers['User-Agent'] = DEFAULT_USERAGENT
        headers['CSeq'] = self._next_cseq()
        headers['Range'] = range
        headers['Scale'] = scale

        self.sendmsg('PLAY', self._url, headers)
        data = self.sock.recv(self._buffer_size).decode(self.encoding)
        code, message, headers, body = self.parse_response(data)
        self._paly_time = self._time = int(time.time())
        self.send_heart_beat_msg()

    def do_options(self):
        headers = dict()
        headers['User-Agent'] = DEFAULT_USERAGENT
        headers['CSeq'] = self._next_cseq()

        self.sendmsg('OPTIONS', self._url, headers)

    def do_teardown(self):
        headers = dict()
        headers['User-Agent'] = DEFAULT_USERAGENT
        headers['CSeq'] = self._next_cseq()

        self.sendmsg('TEARDOWN', self._url, headers)
        self.shutdown()
        time.sleep(0.1)

    def wait_data_udp(self, timeout=10):
        if self._shutdown is True: return

        self.udpsock.settimeout(timeout)
        _timeout_num = 0

        while True:
            if self._duration != 0 and int(time.time()) - self._paly_time > self._duration and self._shutdown is False:
                self.do_teardown()
            rs, ws ,es = select.select([self.sock,], [], [], 0)
            if rs:
                tcpdata = self.sock.recv(self._buffer_size).decode(self.encoding)
                if not tcpdata:
                    if self._shutdown is False:
                        logging.error('tcp rec no data')
                    break
                logging.debug('recv tcp data %d'%len(tcpdata))
                if tcpdata.startswith(RTSP_VERSION):
                    self.parse_response(tcpdata)
                else:
                    command, headers = self.parse_announce(tcpdata)
                    if headers.get('x-reason', None) == '"END"':
                        self.do_teardown()
                    continue
            if self._shutdown is True:
                self.close()
                break
            try:
                udpdata = self.udpsock.recv(self._buffer_size)
                logging.debug('recv udp data %d'%len(udpdata))
                self.write(udpdata)
            except Exception as e:
                logging.error('udp rec no data, err is %s.' % e)
                _timeout_num += 1
            if _timeout_num >= UDP_TIMEOUT_NUM:
                logging.error('udp rec data timeout %d times, exit.' % _timeout_num)
                break

    def wait_data_tcp(self):
        if self._shutdown is True: return
            
        rtsp_resp = _ts_buffer = ''
        while True:
            _to_continue = False
            if self._duration != 0 and int(time.time()) - self._paly_time > self._duration and self._shutdown is False:
                self.do_teardown()
            tcpdata = self.sock.recv(self._buffer_size).decode(self.encoding)
            if not tcpdata:
                if self._shutdown is False:
                    logging.error('tcp rec no data')
                break
            logging.debug('recv tcp data %d'%len(tcpdata))
            for data in tcpdata:
                if hex(ord(data)) == '0x47' and self.bytes == 0:
                    if rtsp_resp.endswith(HEADER_END_STR) is True:
                        if rtsp_resp.startswith(RTSP_VERSION) is True:
                            self.parse_response(rtsp_resp)
                        else:
                            self.parse_announce(rtsp_resp)
                        rtsp_resp = ''
                    elif RTSP_VERSION in rtsp_resp and rtsp_resp.endswith(HEADER_END_STR) is False:
                        rtsp_resp += data
                    else:
                        rtsp_resp = ''
                        _ts_buffer = data
                        self.bytes = 1
                elif self.bytes > 0 and self.bytes < 187 :
                    _ts_buffer += data
                    self.bytes += 1
                elif self.bytes == 187:
                    _ts_buffer += data
                    if self.filehandle is not None:
                        self.write(_ts_buffer.encode(self.encoding))
                    _ts_buffer = ''
                    rtsp_resp = ''
                    self.bytes = 0
                else:
                    if rtsp_resp.endswith(HEADER_END_STR):      
                        if rtsp_resp.startswith(RTSP_VERSION):
                            self.parse_response(rtsp_resp)
                        else:
                            command, headers = self.parse_announce(rtsp_resp)
                            if headers.get('x-reason', None) == '"END"':
                                self.do_teardown()
                                rtsp_resp = data
                                _to_continue = True
                        rtsp_resp = data
                    else:
                        rtsp_resp += data
            if _to_continue is True:
                continue
            if self._shutdown is True:
                self.close()
                break
        if rtsp_resp.endswith(HEADER_END_STR):
            self.parse_response(rtsp_resp)

    def write(self, data):
        if self.filehandle is not None:
            self.filehandle.write(data)

    def shutdown(self):
        self._shutdown = True
        if hasattr(self, '_heartbeat'):
            self._heartbeat.cancel()

    def close(self):
        if self.sock:
            self.sock.close()
            logging.debug('tcp rec data over')
        if self.udpsock:
            self.udpsock.close()
            logging.debug('udp rec data over')
        if self.filehandle is not None:
            self.filehandle.close()
            logging.debug('filehandle close')

    def run(self, range=CUR_RANGE):
        self.do_describe()
        self.do_setup(0)
        self.do_setup(1)
        self.do_play(range=range)
        if self._func is not None:
            self._func()
        return self._retval

if __name__ == '__main__':
    basename = os.path.basename(__file__)
    p = ArgumentParser(usage='Usage: %s [OPTION]... [URL]...' % basename, prog='python-rtsp-client', description='')
    p.add_argument('-t', '--transport',dest='transport',choices=['ts_over_tcp', 'ts_over_udp'], default='ts_over_udp', help='Set transport type when SETUP: ts_over_tcp, ts_over_udp[default]')
    p.add_argument('-w', '--write', dest='write', type=str, help='Set the write parameters when you need to write MPEG2 TS packets to a file')
    p.add_argument('-d', '--dest_ip', dest='dest_ip', help='Set dest ip of udp data transmission, default use localhost')
    p.add_argument('-p', '--client_port', dest='client_port', help='Set client port range when SETUP of udp, default is "10014-10015"')
    p.add_argument('-D', '--duration', dest='duration', type=int, default=0, help='Set duration to limit the playing time')
    p.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    p.add_argument('URL', nargs=1, help='rtsp protocol play url')
    args, remaining = p.parse_known_args()

    if args.dest_ip:     DEST_IP = args.dest_ip
    if args.client_port: CLIENT_PORT_RANGE = args.client_port
    if args.duration:    DURATION = args.duration
    if args.write:       FILEHANDLE = open(args.write, 'wb')

    RTSPURL = args.URL[0]
    TRANSPORT_TYPE = args.transport

    c = RTSPClient(RTSPURL, dst_ip=DEST_IP, port=CLIENT_PORT_RANGE, filehandle=FILEHANDLE, duration=DURATION)
    RETVAL = c.run()
    sys.exit(RETVAL)
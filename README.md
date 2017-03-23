# python-rtsp-client
The rtsp protocol plays the client tool

usage: Usage: 3.py [OPTION]... [URL]...

positional arguments:
  URL                   rtsp protocol play url

optional arguments:
  -h, --help            show this help message and exit
  -t {ts_over_tcp,ts_over_udp}, --transport {ts_over_tcp,ts_over_udp}
                        Set transport type when SETUP: ts_over_tcp,
                        ts_over_udp[default]
  -w WRITE, --write WRITE
                        Set the write parameters when you need to write MPEG2
                        TS packets to a file
  -d DEST_IP, --dest_ip DEST_IP
                        Set dest ip of udp data transmission, default use
                        localhost
  -p CLIENT_PORT, --client_port CLIENT_PORT
                        Set client port range when SETUP of udp, default is
                        "10014-10015"
  -D DURATION, --duration DURATION
                        Set duration to limit the playing time
  -v, --version         show program's version number and exit

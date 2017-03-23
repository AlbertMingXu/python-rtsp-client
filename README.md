# python-rtsp-client
The rtsp protocol plays the client tool<br>

usage: Usage: python-rtsp-client.py [OPTION]... [URL]...<br>
<br>
positional arguments:<br>
　URL                   rtsp protocol play url<br>
<br>
optional arguments:<br>
　-h, --help            show this help message and exit<br>
　-t {ts_over_tcp,ts_over_udp}, --transport {ts_over_tcp,ts_over_udp}<br>
　　　　　　　　　　　　　Set transport type when SETUP: ts_over_tcp,<br>
　　　　　　　　　　　　　ts_over_udp[default]<br>
　-w WRITE, --write WRITE<br>
　　　　　　　　　　　　　Set the write parameters when you need to write MPEG2<br>
　　　　　　　　　　　　　TS packets to a file<br>
　-d DEST_IP, --dest_ip DEST_IP<br>
　　　　　　　　　　　　　Set dest ip of udp data transmission, default use<br>
　　　　　　　　　　　　　localhost<br>
　-p CLIENT_PORT, --client_port CLIENT_PORT<br>
　　　　　　　　　　　　　Set client port range when SETUP of udp, default is<br>
　　　　　　　　　　　　　"10014-10015"<br>
　-D DURATION, --duration DURATION<br>
　　　　　　　　　　　　　Set duration to limit the playing time<br>
　-v, --version         show program's version number and exit<br>

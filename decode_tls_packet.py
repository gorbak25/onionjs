#!/usr/bin/env python3

from scapy import *
from scapy_ssl_tls.ssl_tls import TLS

import base64

user_input = input("Enter b64 encoded data: ")
data = base64.b64decode(user_input)

TLS(data).show()


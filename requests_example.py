import ssl

import requests
import requests.adapters

CIPHERS = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
CIPHERS += ':ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
CIPHERS += ':ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
CIPHERS += ':ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA'
CIPHERS += ':ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA'
CIPHERS += ':AES128-GCM-SHA256:AES256-GCM-SHA384'
CIPHERS += ':AES128-SHA:AES256-SHA'


class SSLContextAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(CIPHERS)
        kwargs['ssl_context'] = ssl_context
        return super(SSLContextAdapter, self).init_poolmanager(*args, **kwargs)


# use defaults
resp = requests.get("https://example.com")
print("resp 1", resp)

# Cipher Suites (43 suites)
#     Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
#     Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
#     Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)
#     Cipher Suite: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xc0af)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xc0ad)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xc0ae)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xc0ac)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CCM_8 (0xc0a3)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CCM (0xc09f)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CCM_8 (0xc0a2)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CCM (0xc09e)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
#     Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
#     Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
#     Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
#     Cipher Suite: TLS_RSA_WITH_AES_256_CCM_8 (0xc0a1)
#     Cipher Suite: TLS_RSA_WITH_AES_256_CCM (0xc09d)
#     Cipher Suite: TLS_RSA_WITH_AES_128_CCM_8 (0xc0a0)
#     Cipher Suite: TLS_RSA_WITH_AES_128_CCM (0xc09c)
#     Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)
#     Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)
#     Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
#     Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
#     Cipher Suite: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)


s = requests.Session()
s.mount('https://example.com', SSLContextAdapter())
resp = s.get('https://example.com')
print("resp 2", resp)

# Cipher Suites (18 suites)
#     Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
#     Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
#     Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
#     Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
#     Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
#     Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
#     Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
#     Cipher Suite: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)


# Chrome:

# Cipher Suites (16 suites)
#     Cipher Suite: Reserved (GREASE) (0x2a2a)
#     Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
#     Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
#     Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
#     Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
#     Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
#     Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
#     Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
#     Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
#     Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)

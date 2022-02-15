## BoringSSL with Python CFFI to look like Chrome

Using `requests` in `requests_example.py`, you can see by default 43 suites are sent in the Client Hello, which doesn't look anything like Chrome's 16 (or Firefox). Using `set_ciphers`, you can get closer, but the order isn't the same, and GREASE isn't included.

`Requests` https://github.com/psf/requests uses `urllib3` https://github.com/urllib3/urllib3 which depends on `pyOpenSSL` / `cryptography`, which uses Python's standard library SSL module https://docs.python.org/3/library/ssl.html . It's likely to be linked to OpenSSL 1.1.1, but that probably depends on your OS.

Go has its own standard TLS library, so it was forked to make modifications https://github.com/refraction-networking/utls . You could call a Go executable from python, but that might not cleanly integrate with your existing python code.

Looking for alternative TLS libraries, Chrome uses BoringSSL, and Firefox uses NSS. BoringSSL is a fork of OpenSSL, so it should be easier to swap in than NSS.

I figured that if I built BoringSSL as a shared library, I should be able to use it from Python via ctypes/cffi/cython. I used manylinux and Github Actions to create a binary wheel and upload it to testpypi: https://github.com/jonatron/boringssl/commit/75241956b3d748888ae4906f45ded14b120dc999 . There's only a wheel for x86_64 linux python3.6 currently, but it should be widely compatible.

I validated the idea by writing a very basic HTTP1.1 client using a raw socket, in `http11_client.py`.

Looking at alternatives to requests, I found the excellent https://github.com/encode/httpcore and https://github.com/encode/httpx/ .
It was easy to write a NetworkBackend for httpcore, `boring_backend.py` is less than 150 lines total.

**This isn't ready to use, for example certificate validation and closing sockets is missing.**

You can try out `core_h2.py` by running:
`python3 -m venv venv`
`source venv/bin/activate`
`pip install -i https://test.pypi.org/simple/ boringssl-binary-build`
`pip install -r requirements.txt`
`python core_h2.py`
In the future, if requirements.txt breaks, use frozen_requirements.txt .

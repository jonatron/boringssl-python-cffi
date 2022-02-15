import os
import typing
from types import SimpleNamespace

import boringssl_binary_build
from cffi import FFI
from httpcore.backends.base import NetworkBackend, NetworkStream
from httpcore import ConnectError

ffi = FFI()

ffi.cdef("""

//void * memset ( void * ptr, int value, size_t num );

// boringssl/include/openssl/base.h
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;

typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;

// boringssl/include/openssl/ssl.h
SSL *SSL_new(SSL_CTX *ctx);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
int SSL_connect(SSL *ssl);
const SSL_METHOD *TLS_method(void);

int SSL_set_tlsext_host_name(SSL *ssl, const char *name);
void SSL_CTX_set_grease_enabled(SSL_CTX *ctx, int enabled);
int SSL_CTX_set_strict_cipher_list(SSL_CTX *ctx, const char *str);
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const uint8_t *protos, unsigned protos_len);
void SSL_get0_alpn_selected(const SSL *ssl, const uint8_t **out_data, unsigned *out_len);
int SSL_set_alpn_protos(SSL *ssl, const uint8_t *protos, unsigned protos_len);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_read(SSL *ssl, void *buf, int num);

int SSL_do_handshake(SSL *ssl);
int SSL_get_error(const SSL *ssl, int ret_code);

// BIO = basic input output
// include/openssl/bio.h
BIO *BIO_new(const BIO_METHOD *method);
BIO *BIO_new_socket(int fd, int close_flag);
BIO *BIO_new_connect(const char *host_and_optional_port);

int BIO_write_all(BIO *bio, const void *data, size_t len);
int BIO_read(BIO *bio, void *data, int len);
""")

BIO_NOCLOSE = 0
BIO_CLOSE = 1

lib_path = os.path.join(boringssl_binary_build.__path__[0], '..', 'boringssl.cpython-36m-x86_64-linux-gnu.so')
bssl = ffi.dlopen(lib_path)


class BoringStream(NetworkStream):
    def __init__(self, ssl_p, ctx_p) -> None:
        self._ssl_p = ssl_p
        self._ctx_p = ctx_p

    def read(self, max_bytes: int, timeout: float = None) -> bytes:
        buf = max_bytes * b'\0'
        bytes_read = bssl.SSL_read(self._ssl_p, buf, max_bytes)
        print("bytes_read", bytes_read)
        # print("read buf", buf[:bytes_read])
        return buf[:bytes_read]

    def write(self, buffer: bytes, timeout: float = None) -> None:
        if not buffer:
            return
        while buffer:
            # print("writing buffer", buffer)
            bytes_written = bssl.SSL_write(self._ssl_p, buffer, len(buffer))
            print("bytes_written", bytes_written)
            buffer = buffer[bytes_written:]

    def close(self) -> None:
        pass

    def start_tls(
        self,
        ssl_context,
        server_hostname: str = None,
        timeout: float = None,
    ) -> NetworkStream:
        bssl.SSL_set_tlsext_host_name(self._ssl_p, server_hostname.encode('ascii'))

        ssl_connect_success = bssl.SSL_connect(self._ssl_p)
        print("ssl_connect_success", ssl_connect_success)

        client_ret = bssl.SSL_do_handshake(self._ssl_p)
        print("client_ret", client_ret)
        if client_ret:
            client_err = bssl.SSL_get_error(self._ssl_p, client_ret)
            print("client_err", client_err)

        return self

    def get_extra_info(self, info: str) -> typing.Any:
        if info == "ssl_object":
            buf = ffi.new("uint8_t[]", b"\0" * 10)
            out_data = ffi.new("uint8_t **", buf)
            out_len = ffi.new("unsigned *")
            bssl.SSL_get0_alpn_selected(self._ssl_p, out_data, out_len)
            if out_len[0]:
                proto = bytes(out_data[0][0:out_len[0]]).decode('ascii')
                print("negotiated proto", proto)
                return SimpleNamespace(selected_alpn_protocol=lambda: proto)
            return None


class BoringBackend(NetworkBackend):

    def connect_tcp(
        self, host: str, port: int, timeout: float = None, local_address: str = None
    ) -> NetworkStream:
        address = (host, port)
        source_address = None if local_address is None else (local_address, 0)

        ctx_p = bssl.SSL_CTX_new(bssl.TLS_method())
        ssl_p = bssl.SSL_new(ctx_p)
        bio_p = bssl.BIO_new_connect(f"{host}:{port}".encode('ascii'))
        bssl.SSL_set_bio(ssl_p, bio_p, bio_p)
        alpn = b'\x02h2\x08http/1.1'
        # alpn = b'\x08http/1.1'
        alpn_err = bssl.SSL_set_alpn_protos(ssl_p, alpn, len(alpn))
        bssl.SSL_CTX_set_grease_enabled(ctx_p, 1)
        if alpn_err:
            raise ConnectError(f"SSL alpn set err: {alpn_err}")
        ciphers_err = bssl.SSL_CTX_set_strict_cipher_list(ctx_p, b"ALL:!aPSK:!ECDSA+SHA1:!3DES")

        return BoringStream(ssl_p, ctx_p)

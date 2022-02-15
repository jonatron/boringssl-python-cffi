from cffi import FFI
import os
import socket

import boringssl_binary_build
ffi = FFI()

# see client.cc

ffi.cdef("""
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

ctx_p = bssl.SSL_CTX_new(bssl.TLS_method())
ssl_p = bssl.SSL_new(ctx_p)

ip_addr = socket.gethostbyname("example.com")
bio_p = bssl.BIO_new_connect(f"{ip_addr}:443".encode('ascii'))

bssl.SSL_set_bio(ssl_p, bio_p, bio_p)

bssl.SSL_set_tlsext_host_name(ssl_p, "example.com".encode("ascii"))
bssl.SSL_CTX_set_grease_enabled(ctx_p, 1)
# search chrome for SSL_CTX_set_strict_cipher_list or SSL_CTX_set_cipher_list
# https://github.com/chromium/chromium/blob/7f45ed9654759d01f8fa4aa289b5421843320b86/net/socket/ssl_client_socket_impl.cc#L869
# std::string command("ALL:!aPSK:!ECDSA+SHA1:!3DES");
ciphers_err = bssl.SSL_CTX_set_strict_cipher_list(ctx_p, b"ALL:!aPSK:!ECDSA+SHA1:!3DES")
# alpn
alpn = b'\x08http/1.1'
alpn_err = bssl.SSL_set_alpn_protos(ssl_p, alpn, len(alpn))

# client, calls do handshake
ssl_connect_success = bssl.SSL_connect(ssl_p)
print("ssl_connect_success", ssl_connect_success)

client_ret = bssl.SSL_do_handshake(ssl_p)
print("client_ret", client_ret)
client_err = bssl.SSL_get_error(ssl_p, client_ret)
print("client_err", client_err)

get_data = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
bytes_written = bssl.SSL_write(ssl_p, get_data, len(get_data))
print("bytes_written", bytes_written)

tmpbuf_len = 256

read_len = 256
data = b''
headers_recieved = False
while (read_len == tmpbuf_len) or not headers_recieved:
    headers_recieved = b'\r\n\r\n' in data
    tmpbuf = tmpbuf_len * b'\0'
    read_len = bssl.SSL_read(ssl_p, tmpbuf, tmpbuf_len)
    data += tmpbuf[:read_len]

print(data)
import pdb; pdb.set_trace()
print("end")

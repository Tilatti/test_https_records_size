# HTTPS CLIENT

## Introduction

I written this tool to be able to test several cases during the implementation
of HTTPS (HTTP/1.1) server running on a embedded target.

Some embedded targets don't support the default TLS record size of 16 ko, which
can bring incompatibility problems during the transmission of large data from
the client to the server (the embedded target).
There is several solutions:
* use a custom client (like this tool)
* use chunked transfer (for example Firefox 65 uses one TLS record per chunk, I didn't verify with other browsers). 
* use the TLS Record Size Limit (RLS) extension (not implemented by mbedTLS, see https://github.com/ARMmbed/mbedtls/pull/1088)
This tool helps to investigate the two first solutions, with the following
features:
* Upload data (POST requests) with different sizes of TLS records for the transmission. 
* Upload data (POST requests) with different sizes of chunks.
* Download data (GET requests) with several requests per TLS connection.
We always consider that one HTTP header can be received inside the TLS records
accepted by the embbeded target.

This tool shall not be used in production ! It is only a mean of verification !

## Compilation (GNU/Linux)

LibreSSL/OpenSSL needs to be installed prior the compilation. A shell.nix file is provided for NixOS.

```console
$ make
```

## Usage

```console
https_client --send [-l] [-f tls_record_size] [-c http_chunk_size] hostname http_request
https_client --get [-r number_of_requests] hostname http_request
```

To send a file via POST with chunks of 64 o and TLS records size of 2 Ko

```console
$ https_client --send -f2048 -c64 192.168.210.5 "POST /file.txt" < ./file.txt
```

Same as previously, but with Content-Length field in request (non-conforme to HTTP/1.1 specifications):

```console
$ https_client --send -l -f2048 -c64 192.168.210.5 "POST /file.txt" < ./file.txt
```

To send a file via POST without chunked encoding and the default TLS records size (16 Ko):

```console
$ https_client --send 192.168.210.5 "POST /file.txt" < ./file.txt
```

To get a resource via GET:

```console
$ https_client --get 192.168.210.5 "GET /file.txt"
```

Same as previously, but repeated 32 times within the same connection (without a new handshake):

```console
$ https_client --get -r32 192.168.210.5 "GET /file.txt"
```

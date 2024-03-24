# totp-reverse-proxy
A small go based reverse proxy with support for TLS, TOTP, and logging using session cookies.

## Usage

In Linux you can generate the TOTP key using following command:
```
    SECRET=$(dd if=/dev/urandom|base64|tr -cd 'A-Z2-7'|head -c30)
```

To build and run the proxy:

```                
go build
./totp_reverse_proxy -server $SECRET -upstream http://localhost:8000 &
```

The proxy will write the logs to rotated proxy-access.log file.
To test the TOTP the https://totp.danhersam.com/ can be used.

The current version of the proxy supports following options:

```
Usage of ./totp-reverse-proxy:
  -cert string
        Path to HTTPS Certificate
  -https
        Enable HTTPS
  -key string
        Path to HTTPS key
  -listen string
        Listen address (default ":9090")
  -secret string
        TOTP Secret Key
  -upstream string
        Upstream URL
```            
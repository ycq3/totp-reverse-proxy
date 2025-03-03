# totp-reverse-proxy

A TOTP reverse proxy written in Go.

一个基于 Go 语言编写的TOTP反向代理，支持TLS，使用cookie保持会话。

## Usage

You can use https://www.pipiqiang.cn/tool/google_code to generate the TOTP key.

你可以访问 https://www.pipiqiang.cn/tool/google_code 来生产二维码

In Linux you can generate the TOTP key using following command:
```
    SECRET=$(dd if=/dev/urandom|base64|tr -cd 'A-Z2-7'|head -c16)
```
And for TOTP client like Google Authenticator the QR-code can be generated with help of qrencode tool:

```
    SERVERNAME=external.myhost.domain
    qrencode -t ANSI256 -o - "otpauth://totp/user@$SERVERNAME?secret=$SECRET'
```

To build and run the proxy:

构建并运行代理

```
go build
./totp_reverse_proxy -secret $SECRET -upstream http://localhost:8000 &
```

The proxy will write the logs to rotated proxy-access.log file.  To
test the TOTP the https://totp.danhersam.com/ can be used.

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

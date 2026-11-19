# HTTP Basic authentication over an unencrypted connection

| | |
| --- | --- |
| Finding id | `http-basic-cleartext` |
| Severity | Medium |
| Applies to | TCP ports running plain HTTP |

## What it means

A web server asks for a user name and password using HTTP Basic authentication on a connection that is not encrypted. Basic authentication sends the credentials in a trivially reversible form with every request.

## Why it matters

Anyone who can observe the traffic can read the user name and password. Web interfaces of devices are a common place for this.

## How it is detected

The tool requests the start page over plain HTTP (not HTTPS) and reads the `WWW-Authenticate` response header. If the header begins with `Basic` (any capitalisation), the finding is raised; the evidence is that header value, usually including the realm name. Credentials are never sent.

## Possible false positives

- A server that redirects to HTTPS before it asks for authentication would not send the header on this request and is not reported.

## How to fix

- **Serve the interface over HTTPS** and redirect or disable plain HTTP. **nginx:** `listen 443 ssl;`; **Apache:** a `VirtualHost` on 443 with mod_ssl; **IIS:** add an HTTPS binding and require SSL.
- **Devices (cameras, printers, switches, controllers):** turn on “HTTPS only” in the management settings, or update the firmware if it lacks HTTPS; otherwise keep the interface on an isolated management network.
- Change the passwords that were exposed.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 7617, The Basic HTTP authentication scheme](https://www.rfc-editor.org/rfc/rfc7617)
- [nginx ngx_http_ssl_module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)
- [Apache mod_ssl](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html)

[All findings](index.md)

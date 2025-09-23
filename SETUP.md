# NGINX - External Proxy

For setups behind an external reverse proxy (heavily recommended), using a local CA and self-signed certificates is not required, but also recommended.

After installing `mkcert` through your system package manager:

```bash
mkcert -install
mkcert abc.domain.xyz, bcd.domain.xyz
mv domain.xyz+X-key.pem nginx/certs/key.pem
mv domain.xyz.pem nginx/certs/certificate.pem
```

NGINX will find these certificates automatically and use them when proxying the application. Unless you know what you are doing, editing files under `nginx/configs/` is not recommended.

If preferred, NGINX can be used as a reverse proxy, however an additional `certbot/certbot:latest` container would be required unless other valid SSL certificates are provided under `nginx/certs`.
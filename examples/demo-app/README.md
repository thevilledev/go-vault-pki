This demo application does the following:

- Issues a new certificate from Vault for Common Name `foo.service.consul`.
- Configures go-chi HTTP router to return "welcome" from `/`
- Starts HTTP listener on `0.0.0.0:18080`

This app is also available as
[a container on Dockerhub](https://hub.docker.com/r/vtorhonen/vault-pki-demo-app/).
Run it as follows:

```
$ docker run --rm -d \
    -p 127.0.0.1:18080:18080
    -e VAULT_TOKEN=<your vault token here> \
    -e VAULT_ADDR=https://<your-vault-address-here>:8200 \
    docker.io/vtorhonen/vault-pki-demo-app:latest
```

Then try it out:

```
$ curl -vvvk https://localhost:18080
* SSL connection using TLSv1.2 / ECDHE-ECDSA-AES128-GCM-SHA256
* Server certificate:
*  subject: CN=foo.service.consul
* Using HTTP2, server supports multi-use

< HTTP/2 200
< content-type: text/plain; charset=utf-8
< content-length: 7
< date: Sat, 10 Feb 2018 22:36:59 GMT
<
* Curl_http_done: called premature == 0
* Connection #0 to host localhost left intact
welcome
```
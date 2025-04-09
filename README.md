# BOSH Release for cloud-gov Cloud Foundry Secure Proxy

This proxy adds an nginx layer on top of Cloud Foundry, proxying all requests made to the router.

nginx is configured to do the following:

- Add `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection` and `Strict-Transport-Security` headers
- Redirect HTTP traffic to HTTPS
- Set limits on timeouts and body sizes

## Usage

To use this BOSH release, first upload it to your BOSH:

```shell
bosh target BOSH_HOST
git clone https://github.com/cloud-gov/cg-secureproxy-boshrelease.git
cd cg-secureproxy-boshrelease
bosh upload release releases/secureproxy/secureproxy-5.yml
```

Then add the properties to your manifest file, and add the secureproxy release to the releases section:

```yaml
properties:
  ...
  secureproxy:
    proxy_port: 85
    listen_port: 80
releases:
- ...
- name: secureproxy
  version: latest
```

Change the port the router runs on:

```yaml
properties:
  ...
  router:
    port: 85
```

Finally add the `secureproxy` template to your job:

```yaml
- instances: 1
  name: router_z1
  ...
  templates:
  - ...
  - name: secureproxy
    release: secureproxy
```

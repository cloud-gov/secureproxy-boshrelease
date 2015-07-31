# BOSH Release for 18f Cloud Secure Proxy

This proxy add an nginx layer on top Cloud Foundry proxying all requests made to the router.

Nginx is configured to do the following:

- Add `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection` and `Strict-Transport-Security` headers;
- Redirect HTTP traffic to HTTPS
- Set limits on timeouts and body sizes

## Usage

To use this bosh release, first upload it to your bosh:

```
bosh target BOSH_HOST
git clone https://github.com/18f/secureproxy-boshrelease.git
cd newrelic-boshrelease
bosh upload release releases/secureproxy/secureproxy-5.yml
```

Then add the properties to your manifest file and the secureproxy release to the releases section:

```
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
```
properties:
  ...
  router:
    port: 85
```

Finally add the `secureproxy` template to your job:

```
- instances: 1
  name: router_z1
  ...
  templates:
  - ...
  - name: secureproxy
    release: secureproxy
```

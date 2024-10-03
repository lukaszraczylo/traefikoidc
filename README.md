## Traefik OIDC middleware

This middleware is supposed to replace the need for the forward-auth and oauth2-proxy when using traefik as a reverse proxy to support the OIDC authentication.

Middleware has been tested with Auth0 and Logto.

### Configuration options

Middleware currently supports following scenarios:

* Setting custom callback and logout URLs via `callbackURL` and `logoutURL`
* Allowing for access only from the listed domains if `allowedUserDomains` is set, otherwise it relies entirely on the OIDC provider
* Using excluded URLs which do **NOT** require the OIDC authentication
* Rate limiting requests to prevent the bruteforce attacks

#### How to configure...

##### Excluded URLs with open access

```
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-with-open-urls
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: xxx
      clientID: yyy
      clientSecret: zzz
      sessionEncryptionKey: vvv
      callbackURL: /cool-oidc/callback
      logoutURL: /cool-oidc/logout
      scopes:
        - openid
        - email
        - profile
      excludedURLs: # Determines the list of URLs which are NOT a subject to authentication
        - /login # covers /login, /login/me, /login/reminder etc.
        - /my-public-data
```


##### Allowed email domains

Assuming that your OIDC provider allows anyone to log in, you may want to limit the access to people using emains in specific domain.

```
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-only-my-users
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: xxx
      clientID: yyy
      clientSecret: zzz
      sessionEncryptionKey: vvv
      callbackURL: /new-oidc/callback
      logoutURL: /new-oidc/logout
      scopes:
        - openid
        - email
        - profile
      allowedUserDomains:
        - raczylo.com
```


##### Allowed groups and roles

In case of multiple roles / groups and access separation for various endpoints you will need to create multiple traefik middlewares.
Following example allows access for users who have additional role `guest-endpoints` assigned.

```
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-guest-endpoints
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: xxx
      clientID: yyy
      clientSecret: zzz
      sessionEncryptionKey: vvv
      callbackURL: /my-oidc/callback
      logoutURL: /my-oidc/logout
      scopes:
        - openid
        - email
        - profile
        - roles     # This line queries the OIDC provider for roles
      forceHTTPS: true
      allowedRolesAndGroups:
        - guest-endpoints  # This line specifies the roles or groups allowed to access content
      allowedUserDomains:
        - raczylo.com
```


#### Docker compose example

`docker-compose.yaml`

```yaml
version: "3.7"

services:
  traefik:
    image: traefik:v3.0.1
    command:
      - "--experimental.plugins.traefikoidc.modulename=github.com/lukaszraczylo/traefikoidc"
      - "--experimental.plugins.traefikoidc.version=v0.2.1"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./traefik-config/traefik.yml:/etc/traefik/traefik.yml
      - ./traefik-config/dynamic-configuration.yml:/etc/traefik/dynamic-configuration.yml
    labels:
      - "traefik.http.routers.dash.rule=Host(`dash.localhost`)"
      - "traefik.http.routers.dash.service=api@internal"

    ports:
      - "80:80"

  hello:
    image: containous/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.hello.entrypoints=http
      - traefik.http.routers.hello.rule=Host(`hello.localhost`)
      - traefik.http.services.hello.loadbalancer.server.port=80
      - traefik.http.routers.hello.middlewares=my-plugin@file

  whoami:
    image: jwilder/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.whoami.entrypoints=http
      - traefik.http.routers.whoami.rule=Host(`whoami.localhost`)
      - traefik.http.services.whoami.loadbalancer.server.port=8000
      - traefik.http.routers.whoami.middlewares=my-plugin@file
```

`traefik-config/traefik.yaml`

```yaml
log:
  level: INFO

experimental:
  localPlugins:
    traefikoidc:
      moduleName: github.com/lukaszraczylo/traefikoidc

# API and dashboard configuration
api:
  dashboard: true
  insecure: true

entryPoints:
  http:
    address: ":80"
    forwardedHeaders:
      insecure: true

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
  file:
    filename: /etc/traefik/dynamic-configuration.yml
```

`traefik-config/dynamic-configuration.yaml`
```yaml
http:
  middlewares:
    my-plugin:
      plugin:
        traefikoidc:
          providerURL: https://accounts.google.com
          clientID: 1234567890.apps.googleusercontent.com
          clientSecret: secret
          callbackURL: /oauth2/callback
          logoutURL: /oauth2/logout
          scopes: # If not provided, default scopes will be used (openid, email, profile)
            - openid
            - email
            - profile
          allowedUserDomains: # If not provided - will rely entirely on the OIDC yes/no
            - raczylo.com
          sessionEncryptionKey: potato-secret
          forceHTTPS: false
          logLevel: debug # debug, info, warn, error
          rateLimit: 100 # Simple rate limiter to prevent brute force attacks
          excludedURLs: # Determines the list of URLs which are NOT a subject to authentication
            - /login # covers /login, /login/me, /login/reminder etc.
            - /my-public-data
```

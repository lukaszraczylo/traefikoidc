## Traefik OIDC middleware

WIP warning!
This middleware is under active development.

This middleware is supposed to replace the need for the forward-auth and oauth2-proxy when using traefik as a reverse proxy.

### Configuration options

```
testData:
  providerURL: https://accounts.google.com
  clientID: 1234567890.apps.googleusercontent.com
  clientSecret: secret
  callbackURL: /oauth2/callback
  logoutURL: /oauth2/logout
  scopes:
    - openid
    - email
    - profile
  sessionEncryptionKey: potato-secret
```

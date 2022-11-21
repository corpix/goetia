# goetia

Proxy server which authenticates and authorizes user requests.

**This project is work in progress**

```

 ┌──────┐               ┌────────────┐                    ┌───────────────────┐             ┌───────────────────┐
 │ user │               │ goetia     │                    │ identity-provider │             │ protected-service │
 └──┬───┘               └──────┬─────┘                    └───────────┬───────┘             └──────────┬────────┘
    │                          │                                      │                                │
    │ send HTTP request        │ check whether the session has        │                                │
    │ with/without cookie      │ loggen in user                       │                                │
    ├────────────────────────► ├─────────────────────────────────────────────────────────────────────► │
    │                          │                                      │                                │
    │                          │ passthrough protected-service        │                                │
    │                          │ response                             │                                │
    │ ◄────────────────────────────────────────────────────────────────────────────────────────────────┤
    │                          │                                      │                                │
    │                          │ if user is not logged in then        │                                │
    │                          │ pass to auth connector               │                                │
    │                          ├────────────────────────────────────► │                                │
    │                          │                                      │                                │
    │                          │ authenticating with configured       │                                │
    │                          │ connector & returning back           │                                │
    │ set session cookie       │ ◄────────────────────────────────────┤                                │
    │ containing user profile  │                                      │                                │
    │ ◄────────────────────────┤                                      │                                │
    │                          │                                      │                                │
    │                          │                                      │                                │
```

- `user` is a HTTP client
- `goetia` service of the subject
- `identity-provider` trusted external service which is a provider for user profile
- `protected-service` service which is protected by the proxy

## cookbook

### NixOS Nginx upstream & reverse proxy mode

This mode uses HTTP headers to provide `username` to the upstream.

- goetia on `127.0.0.1:6677`
- backend on `127.0.0.1:8877`

```
    services = {
      nginx = {
        upstreams.backend = {
          servers."127.0.0.1:8877".backup = false;
          extraConfig = "keepalive 16;";
        };
        virtualHosts."backend.example.com" = {
          locations."/robots.txt".return = "200 'User-agent: *\\nDisallow: /'";
          locations."/auth/".proxyPass = "http://127.0.0.1:6677";
          locations."/auth/status" = {
            proxyPass = "http://127.0.0.1:6677";
            extraConfig = ''
              proxy_set_header Content-Length "";
              proxy_pass_request_body off;
              proxy_method GET;
              client_max_body_size 30M;
            '';
          };
          locations."/" = {
            proxyPass = "http://backend";
            extraConfig = ''
              auth_request /auth/status;
              error_page 401 = /auth/signin?retpath=$request_uri;
              auth_request_set $username $upstream_http_x_auth_name;

              proxy_set_header Host $host;
              proxy_set_header Upgrade $http_upgrade;
              proxy_set_header Connection "upgrade";
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Scheme $scheme;
              proxy_set_header X-Auth-Name $username;
              proxy_http_version 1.1;
            '';
          };
        };
      };
    };
```

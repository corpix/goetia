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

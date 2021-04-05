# VerneMQ Auth Plugin

This plugin enables JWT authentication and authorization for VerneMQ. Currently,  MQTT 3.1 and 3.1.1 clients are supported by the plugin. The JWTs need to be signed using the HS512 algorithm.

## How does it work

The plugin uses the claims from the token to authenticate users and authorize them to publish/subscribe to topics.

Example JWT header:
```
{
  "alg": "HS512"
}
```

Example JWT payload:
```
{
  "client-id": "628313875",
  "retain": false,
  "authz": [
    {
      "action": "publish",
      "topic": "test/#"
    },
    {
      "action": "subscribe",
      "topic": "test/#"
    }
  ],
  "exp": 1893452400
}
```

## Build

```
./rebar3 compile
```

Enabling the plugin:

```
vmq-admin plugin enable --name vernemq_auth_plugin --path <PathToYourPlugin>/vernemq_auth_plugin/_build/default
```

## Try it out

Connecting and publishin using the mosquitto client (send the JWT as the password):
```
mosquitto_pub -u user -P eyJhbGciOiJIUzUxMiJ9.eyJjbGllbnQtaWQiOiI2MjgzMTM4NzUiLCJyZXRhaW4iOmZhbHNlLCJhdXRoeiI6W3siYWN0aW9uIjoicHVibGlzaCIsInRvcGljIjoidGVzdC8jIn0seyJhY3Rpb24iOiJzdWJzY3JpYmUiLCJ0b3BpYyI6InRlc3QvIyJ9XSwiZXhwIjoxODkzNDUyNDAwfQ.q6B110KrhaHM4XBzJHZNrB9RYYQbPJemJ82Er0l1a3Kh-ndBrPY6NHCnZIzR3rIOwAkD0zAYEX8OZPO-jceUfg -i 628313875 --repeat 100 --repeat-delay 1 -m "message" -t test -d
```
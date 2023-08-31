# HTTP/2 Antifingerprint

Allows to create `ClientHttp2Session` with passive fingerprint evasion by changing JA3, HTTP/2 options, header order and pseudo-header order.

## Example

```javascript
const http2antifingerprint = require("http2-antifingerprint"); // default import
const { http2antifingerprint } = require("http2-antifingerprint"); // particular import

(async () => {
  const options = {
    proxy: {
      scheme: "http",
      user: "user", // Is not mandatory
      password: "password", // Is not mandatory
      host: "example.com",
      port: 80,
    },
    onSwitchingProtocols: (response) => console.log(response.statusCode), // Callback is fired on connection upgrade
  };

  const listener = () => {};

  const client = await http2antifingerprint.connect(
    "https://example.com",
    listener,
    options
  ); // Returns a Promise
  client.on("error", (err) => console.error(err)); // Methods of node:http2 session are left intact

  const request = client.request(
    {
      ":method": "POST",
      ":authority": "example.com",
      ":scheme": "https",
      ":path": "/",
      "user-agent": "node",
      "accept-encoding": "gzip, deflare, br",
      "accept-language": "en-US",
    },
    {}, // Client session request options from node:http2
    {
      reorderPseudoHeaders: true, // Headers starting with colon will be reordered
      reorderHeaders: false, // All other headers that do not start with colon will not be reordered
      preferChromeHeaderOrder: true, // The headers provided will maintain chrome header order that depend on the http method
    }
  );

  // Further API is left intact

  request.on("response", (headers) => {
    for (const name in headers) {
      console.log(`${name}: ${headers[name]}`);
    }
  });

  request.setEncoding("utf8");
  let data = "";
  request.on("data", (chunk) => {
    data += chunk;
  });
  request.on("end", () => {
    console.log(`\n${data}`);
    client.close();
  });
  request.end();
})();
```

## API

### Creating a HTTP/2 session

`await http2antifingerprint.connect([authority], [listener], [options])`

Returns a `Promise<ClientHttp2Session>`.

- `[authority]` - the remote HTTP/2 server to connect to. This must be in the form of a minimal, valid URL with the http:// or https:// prefix, host name, and IP port (if a non-default port is used). Userinfo (user ID and password), path, querystring, and fragment details in the URL will be ignored.
- `[listener]` - will be registered as a one-time listener of the 'connect' event. Not mandatory.
- `[options]` - not a mandatory argument.

`[options]` can have `proxy` object consisting of `scheme`, `host` and `port` and may contain `user` or `password` properties.

`[options]` can have `onSwitchingProtocols` callback that is getting called with the `http.IncomingMessage` argument. Since `1.1.4` supports any `http2` option, such as `createConnection`.
Can have `tlsConnectOverrides` that override the existing default TLS values. Might be useful for encryption setting override or for custom ALPN protocols:

```js
const options = {
  tlsConnectOverrides: {
    ALPNProtocols: ["h2", "http/1.1", "spdy/3.1"],
  },
};
const client = await http2antifingerprint.connect(
  "https://example.com",
  listener,
  options
);
```

### Creating a request

`const request = client.request([headers], [client session options], [header options]);`

- `[headers]` - an object that contains key-value pairs of pseudo-headers and headers.
- `[client session options]` - the same semantics as in `node:http2` built-in package. Can be an empty object.
- `[header options]` - not a mandatory argument that can have `reorderPseudoHeaders` and `reorderHeaders` boolean properties. Both are `true` by default.

Fallbacks to parent's client session options if `[header options]` are not specified.

Can have `preferChromeHeaderOrder` property that cannot be used with `reorderPseudoHeaders` or with `reorderHeaders` properties.
In such case, header ordering will be chrome, because many sites reject non-chrome header orders or detect bots with it. Defaults to `false`

- `reorderPseudoHeaders` defaults to `true`
- `reorderHeaders` defaults to `true`

Can have `strictMode` boolean property. If specified, the `client.request` method call without second and third arguments will reject with error.
`false` by default.

`negotiationSpoof` allows to spoof `tls`'s `secureProtocol` and `sigals` list during client hello stage, if set to `true`. Defaults to `false`.

**Notice**: if `preferChromeHeaderOrder` is `true`, it is not required to set `reorderPseudoHeaders` and `reorderHeaders` properties to `false` as they will default to `false`.

## Test

```js
npm test
```

const http = require("node:http");
const http2 = require("node:http2");

const tls = require("node:tls");

const {
  AntiFingerprintClientSessionOptions,
} = require("./options/AntiFingerprintClientSessionOptions.js");

const { randint } = require("./randint.js");

async function connect(authority, listener, options) {
  let isAuthenticatedProxy = false;
  let proxy = "";
  let optionsProxy;
  let onSwitchingProtocols = () => {};

  if (typeof options === "object") {
    optionsProxy = options.proxy;

    if (optionsProxy) {
      if (optionsProxy.user || optionsProxy.password) {
        isAuthenticatedProxy = true;
        proxy = `${optionsProxy.scheme}://${optionsProxy.user}:${optionsProxy.password}@${optionsProxy.host}:${optionsProxy.port}`;
      } else {
        proxy = `${optionsProxy.scheme}://${optionsProxy.host}:${optionsProxy.port}`;
      }
    }

    const optionsOnSwitchingProtocols = options.onSwitchingProtocols;

    if (optionsOnSwitchingProtocols) {
      onSwitchingProtocols = optionsOnSwitchingProtocols;
    }
  }

  let client;

  const port = authority.startsWith("http://") ? 80 : 443;

  const host = authority.includes("http://")
    ? authority.split("http://")[1]
    : authority.split("https://")[1];

  if (proxy) {
    const headers = {};
    if (isAuthenticatedProxy) {
      headers["Proxy-Authorization"] = `Basic ${Buffer.from(
        optionsProxy.user + ":" + optionsProxy.password
      ).toString("base64")}`;
    }
    const request = http.request({
      method: "CONNECT",
      host: optionsProxy.host,
      port: optionsProxy.port,
      path: `${host}:${port}`,
      headers,
    });
    request.end();

    client = await new Promise((resolve) => {
      request.on("connect", (response, socket) => {
        onSwitchingProtocols(response);
        resolve(
          http2.connect(authority, {
            createConnection: () =>
              tls.connect({
                host,
                socket: socket,
                ALPNProtocols: ["h2"],
              }),
          })
        );
      });
    });
  } else {
    client = http2.connect(
      authority,
      new AntiFingerprintClientSessionOptions().get(),
      listener
    );
  }

  const originalRequest = client.request;

  client.request = (headers, options) => {
    const newHeaders = {};
    const keys = Object.getOwnPropertyNames(headers).sort(() =>
      !!randint(0, 1) ? -1 : 1
    );

    for (const key of keys) {
      newHeaders[key] = headers[key];
    }

    return originalRequest.call(client, newHeaders, options);
  };

  return client;
}

module.exports = {
  connect,
};

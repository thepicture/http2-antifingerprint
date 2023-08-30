const http = require("node:http");
const http2 = require("node:http2");

const tls = require("node:tls");

const config = require("./options/const");

const {
  AntiFingerprintClientSessionOptions,
} = require("./options/AntiFingerprintClientSessionOptions.js");

const { shuffle } = require("./shuffle.js");

async function connect(authority, listener, options) {
  let isAuthenticatedProxy = false;
  let proxy = "";
  let optionsProxy;

  if (options) {
    this._http2antifingerprintListener = listener;
    this._http2antifingerprintOptions = options;

    optionsProxy = options.proxy;

    if (optionsProxy?.user || optionsProxy?.password) {
      isAuthenticatedProxy = true;

      proxy = `${optionsProxy.scheme}://${optionsProxy.user}:${optionsProxy.password}@${optionsProxy.host}:${optionsProxy.port}`;
    } else if (optionsProxy) {
      proxy = `${optionsProxy.scheme}://${optionsProxy.host}:${optionsProxy.port}`;
    }

    onSwitchingProtocols = options.onSwitchingProtocols || (() => {});
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
        `${optionsProxy.user}:${optionsProxy.password}`
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
            createConnection:
              options.createConnection ||
              (() =>
                tls.connect({
                  host,
                  socket: socket,
                  ALPNProtocols: ["h2"],
                  ...tlsConnectOverrides,
                })),
          })
        );
      });
    });
  } else {
    const sessionOptions = {
      ...new AntiFingerprintClientSessionOptions().get({
        ...(options?.tlsConnectOverrides && {
          tlsConnectOverrides: options?.tlsConnectOverrides,
        }),
      }),
      ...options,
    };

    client = http2.connect(authority, sessionOptions, listener);
  }

  client._http2antifingerprintOptions = this._http2antifingerprintOptions;
  client._http2antifingerprintListener = this._http2antifingerprintListener;

  const originalRequest = client.request;

  client.request = (headers, options, antifingerprintOptions) => {
    let reorderHeaders = true;
    let reorderPseudoHeaders = true;
    let preferChromeHeaderOrder = false;

    const isWrongMethodCallInStrictMode =
      this._http2antifingerprintOptions?.strictMode &&
      !(antifingerprintOptions && options);

    if (isWrongMethodCallInStrictMode) {
      throw new Error(
        "client.request requires " +
          "options in strict mode. " +
          "Usage: client.request([headers], [client session options], [header options])"
      );
    }

    const mergedOptions = {
      ...antifingerprintOptions,
      ...this._http2antifingerprintOptions,
    };

    const {
      reorderHeaders: optionsReorderHeaders,
      reorderPseudoHeaders: optionsReorderPseudoHeaders,
    } = mergedOptions;

    if (optionsReorderHeaders) {
      reorderHeaders = optionsReorderHeaders;
    }

    if (optionsReorderPseudoHeaders) {
      reorderPseudoHeaders = optionsReorderPseudoHeaders;
    }

    if (mergedOptions.preferChromeHeaderOrder) {
      preferChromeHeaderOrder = true;
    }

    const areImpossibleOptions =
      (mergedOptions.reorderPseudoHeaders || mergedOptions.reorderHeaders) &&
      preferChromeHeaderOrder;

    if (areImpossibleOptions) {
      throw new Error(
        "preferChromeHeaderOrder cannot be used with reorderPseudoHeaders or reorderHeaders at same time"
      );
    }

    if (preferChromeHeaderOrder) {
      const pseudoHeadersBefore = Object.keys(headers);

      const isMethodWithPostBody = ["post", "put", "patch"].some(
        (verb) =>
          headers[http2.constants.HTTP2_HEADER_METHOD]?.toLowerCase() ===
          verb.toLowerCase()
      );

      const configEntry = isMethodWithPostBody ? "post" : "get";

      const specimenHeaderOrder = config.order.chrome[configEntry].header.order;

      const headersAfter = {};

      for (const pseudoHeaderName of specimenHeaderOrder.pseudo) {
        if (pseudoHeadersBefore.includes(pseudoHeaderName)) {
          headersAfter[pseudoHeaderName] = headers[pseudoHeaderName];
        }
      }

      for (const headerName of specimenHeaderOrder.http) {
        if (pseudoHeadersBefore.includes(headerName)) {
          headersAfter[headerName] = headers[headerName];
        }
      }

      return originalRequest.call(client, headersAfter, options);
    }

    const newHeaders = {};
    let keys = Object.getOwnPropertyNames(headers);

    if (reorderPseudoHeaders) {
      keys = [
        ...shuffle(keys.filter((key) => key.startsWith(":"))),
        ...keys.filter((key) => !key.startsWith(":")),
      ];
    }

    if (reorderHeaders) {
      keys = [
        ...keys.filter((key) => key.startsWith(":")),
        ...shuffle(keys.filter((key) => !key.startsWith(":"))),
      ];
    }

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

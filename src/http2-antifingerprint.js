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
  let onSwitchingProtocols = () => {};

  if (typeof options === "object") {
    this._http2antifingerprintListener = listener;
    this._http2antifingerprintOptions = options;
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
            createConnection:
              options.createConnection ||
              (() =>
                tls.connect({
                  host,
                  socket: socket,
                  ALPNProtocols: ["h2"],
                })),
          })
        );
      });
    });
  } else {
    let sessionOptions = new AntiFingerprintClientSessionOptions().get();

    if (options) {
      sessionOptions = {
        ...sessionOptions,
        ...options,
      };
    }

    client = http2.connect(authority, sessionOptions, listener);
  }

  const originalRequest = client.request;

  client.request = (headers, options, antifingerprintOptions) => {
    let reorderHeaders = true;
    let reorderPseudoHeaders = true;
    let preferChromeHeaderOrder = false;

    const fallbackOptions =
      antifingerprintOptions || this._http2antifingerprintOptions;

    if (typeof fallbackOptions === "object") {
      const optionsReorderHeaders = fallbackOptions.reorderHeaders;
      const optionsReorderPseudoHeaders = fallbackOptions.reorderPseudoHeaders;

      if (typeof optionsReorderHeaders !== "undefined") {
        reorderHeaders = optionsReorderHeaders;
      }

      if (typeof optionsReorderPseudoHeaders !== "undefined") {
        reorderPseudoHeaders = optionsReorderPseudoHeaders;
      }
    }

    if (fallbackOptions.preferChromeHeaderOrder) {
      preferChromeHeaderOrder = true;
    }

    const areImpossibleOptions =
      (fallbackOptions.reorderPseudoHeaders ||
        fallbackOptions.reorderHeaders) &&
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

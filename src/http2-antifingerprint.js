const http2 = require("node:http2");

const {
  AntiFingerprintClientSessionOptions,
} = require("./options/AntiFingerprintClientSessionOptions.js");

const { randint } = require("./randint.js");

function connect(authority, listener) {
  const client = http2.connect(
    authority,
    new AntiFingerprintClientSessionOptions().get(),
    listener
  );

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

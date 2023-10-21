"use strict";

const tls = require("node:tls");
const http = require("node:http");
const http2 = require("node:http2");
const { getCurves, constants } = require("node:crypto");

const { shuffle } = require("./shuffle");
const { randint, seedint } = require("./randint");
const { bitmask } = require("./bitmask");
const config = require("./options/const");
const {
  AntiFingerprintClientSessionOptions,
} = require("./options/AntiFingerprintClientSessionOptions");

async function connect(authority, listener, options) {
  let proxy = "";
  let optionsProxy;
  let isAuthenticatedProxy = false;
  let onSwitchingProtocols = () => {};

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

    onSwitchingProtocols = options.onSwitchingProtocols || onSwitchingProtocols;
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
                  servername: host,
                  socket: socket,
                  ALPNProtocols: ["h2"],
                  ...(options?.negotiationSpoof && getNegotiationSpoofProps()),
                  ...(options?.curveSpoof && getCurveSpoofProps()),
                  ...(options?.spoofSecureOptions && getSecureOptions()),
                  ...tlsConnectOverrides,
                })),
            ...(options.ca && { ca: options.ca }),
          })
        );
      });
    });
  } else {
    this._http2antifingerprintSessionOptions = {
      ...(options?.tlsConnectOverrides && {
        tlsConnectOverrides: options?.tlsConnectOverrides,
      }),
      ...(options?.negotiationSpoof && getNegotiationSpoofProps()),
      ...(options?.curveSpoof && getCurveSpoofProps()),
      ...(options?.spoofSecureOptions && getSecureOptions()),
      ...(options?.spoofHonorCipherOrder && getSpoofHonorCipherOrderProps()),
    };

    const seedHistory = typeof options?.seed === "number" ? [] : null;

    const sessionOptions = {
      ...new AntiFingerprintClientSessionOptions().get(
        this._http2antifingerprintSessionOptions,
        typeof options?.seed === "number" ? [options.seed] : null,
        seedHistory
      ),
      ...(options?.ca && { ca: options.ca }),
      ...options,
    };

    client = http2.connect(authority, sessionOptions, listener);

    if (seedHistory) {
      client._http2antifingerprint = {
        seedHistory,
      };
    }
  }

  client._http2antifingerprintOptions = this._http2antifingerprintOptions;
  client._http2antifingerprintListener = this._http2antifingerprintListener;
  client._http2antifingerprintSessionOptions =
    this._http2antifingerprintSessionOptions;

  const { request: originalRequest } = client;

  const seedRef = [options?.seed];

  client.request = (headers, options, antifingerprintOptions) => {
    let reorderHeaders = true;
    let reorderPseudoHeaders = true;
    let banOriginalHeaderOrder = false;
    let preferChromeHeaderOrder = false;
    let banOriginalPseudoHeaderOrder = false;

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
      banOriginalHeaderOrder: optionsBanOriginalHeaderOrder,
      banOriginalPseudoHeaderOrder: optionsBanOriginalPseudoHeaderOrder,
      isRequestDependsOnSeed: optionsIsRequestDependsOnSeed,
    } = mergedOptions;

    if (optionsIsRequestDependsOnSeed !== undefined) {
      const settings = {
        headerTableSize: seedint(0, 2 ** 16 - 1, seedRef),
        enablePush: !!seedint(0, 1, seedRef),
        initialWindowSize: seedint(0, 2 ** 16 - 1, seedRef),
        maxFrameSize: seedint(1, 2 ** 24 - 1, seedRef),
        maxConcurrentStreams: seedint(0, 2 ** 16 - 1, seedRef),
        maxHeaderListSize: seedint(0, 2 ** 16 - 1, seedRef),
        enableConnectProtocol: !!seedint(0, 1, seedRef),
      };

      client._http2antifingerprint.seedHistory.push(settings);

      client.settings(settings);
    }

    if (optionsReorderHeaders !== undefined) {
      reorderHeaders = optionsReorderHeaders;
    }

    if (optionsReorderPseudoHeaders !== undefined) {
      reorderPseudoHeaders = optionsReorderPseudoHeaders;
    }

    if (optionsBanOriginalHeaderOrder !== undefined) {
      banOriginalHeaderOrder = optionsBanOriginalHeaderOrder;
    }

    if (optionsBanOriginalPseudoHeaderOrder !== undefined) {
      banOriginalPseudoHeaderOrder = optionsBanOriginalPseudoHeaderOrder;
    }

    if (mergedOptions.preferChromeHeaderOrder !== undefined) {
      preferChromeHeaderOrder = mergedOptions.preferChromeHeaderOrder;
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
    let originalKeys = Object.getOwnPropertyNames(headers);
    let keys = [...originalKeys];

    if (reorderPseudoHeaders) {
      do {
        keys = [
          ...shuffle(keys.filter((key) => key.startsWith(":"))),
          ...keys.filter((key) => !key.startsWith(":")),
        ];
      } while (
        banOriginalPseudoHeaderOrder &&
        keys.every((key, index) => originalKeys[index] === key)
      );
    }

    if (reorderHeaders) {
      do {
        keys = [
          ...keys.filter((key) => key.startsWith(":")),
          ...shuffle(keys.filter((key) => !key.startsWith(":"))),
        ];
      } while (
        banOriginalHeaderOrder &&
        keys.every((key, index) => originalKeys[index] === key)
      );
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

const getNegotiationSpoofProps = () => ({
  negotiationSpoof: true,
  secureProtocol: shuffle([
    "TLSv1_1_method",
    "TLSv1_2_method",
    "TLSv1_3_method",
  ]).slice(randint(0, 2)),
  sigalgs: shuffle([
    "ecdsa_sha1",
    "rsa_pkcs1_sha1",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
  ])
    .slice(randint(0, 7))
    .join(":"),
});

const getCurveSpoofProps = () => {
  const curves = getCurves();

  return {
    curveSpoof: true,
    ecdhCurve: shuffle(curves)
      .slice(randint(0, curves.length - 2))
      .join(":"),
  };
};

const getSecureOptions = () => ({
  spoofSecureOptions: true,
  secureOptions: bitmask(
    shuffle([
      constants.SSL_OP_ALL,
      constants.SSL_OP_NO_SSLv2,
      constants.SSL_OP_NO_SSLv3,
      constants.SSL_OP_NO_TICKET,
      constants.SSL_OP_NO_COMPRESSION,
      constants.SSL_OP_CRYPTOPRO_TLSEXT_BUG,
      constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
      constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
    ]).slice(randint(0, 6))
  ),
});

const getSpoofHonorCipherOrderProps = () => ({
  spoofHonorCipherOrder: true,
  honorCipherOrder: Math.random() > 0.5,
});

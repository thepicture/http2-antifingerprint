"use strict";

const tls = require("node:tls");

const { randint, seedint } = require("../randint");

const HTTPS_PORT = 443;
class AntiFingerprintClientSessionOptions {
  get = (options = {}, seedRef, seedHistory) => {
    const settings = Array.isArray(seedRef)
      ? {
          headerTableSize: seedint(0, 2 ** 16 - 1, seedRef),
          enablePush: !!seedint(0, 1, seedRef),
          initialWindowSize: seedint(0, 2 ** 16 - 1, seedRef),
          maxFrameSize: seedint(16384, 2 ** 24 - 1, seedRef),
          maxConcurrentStreams: seedint(0, 2 ** 16 - 1, seedRef),
          maxHeaderListSize: seedint(0, 2 ** 16 - 1, seedRef),
          enableConnectProtocol: !!seedint(0, 1, seedRef),
        }
      : {
          headerTableSize: randint(0, 2 ** 16 - 1),
          enablePush: !!randint(0, 1),
          initialWindowSize: randint(0, 2 ** 16 - 1),
          maxFrameSize: randint(16384, 2 ** 24 - 1),
          maxConcurrentStreams: randint(0, 2 ** 16 - 1),
          maxHeaderListSize: randint(0, 2 ** 16 - 1),
          enableConnectProtocol: !!randint(0, 1),
        };

    if (seedHistory) {
      seedHistory.push(settings);
    }

    return {
      settings,
      createConnection: (url) => {
        const ciphers = tls.getCiphers().slice(0, 16);

        ciphers.sort(() => (!!randint(0, 1) ? 1 : -1));

        for (let i = 0; i < randint(0, 2); i++) {
          ciphers.pop();
        }

        const clonedOptions = { ...options };

        if (clonedOptions.negotiationSpoof) {
          delete clonedOptions.negotiationSpoof;
        }

        if (clonedOptions.curveSpoof) {
          delete clonedOptions.curveSpoof;
        }

        if (clonedOptions.spoofSecureOptions) {
          delete clonedOptions.spoofSecureOptions;
        }

        if (clonedOptions.spoofHonorCipherOrder) {
          delete clonedOptions.spoofHonorCipherOrder;
        }

        const { port } = url;

        return tls.connect(port.length ? Number(port) : HTTPS_PORT, url.host, {
          servername: url.host,
          ALPNProtocols: ["h2"],
          ciphers: ciphers.join(":").toUpperCase(),
          ...clonedOptions.tlsConnectOverrides,
        });
      },
    };
  };
}

module.exports = {
  AntiFingerprintClientSessionOptions,
};

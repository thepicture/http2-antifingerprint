"use strict";

const tls = require("node:tls");
const { randint, seedint } = require("../randint");

const HTTPS_PORT = 443;
const IGNORED_FIELD_NAMES = [
  "negotiationSpoof",
  "curveSpoof",
  "spoofSecureOptions",
  "spoofHonorCipherOrder",
];

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
      createConnection: ({ port, host, hostname }) => {
        const ciphers = tls.getCiphers().slice(0, 16);

        ciphers.sort(() => (!!randint(0, 1) ? 1 : -1));

        for (let i = 0; i < randint(0, 2); i++) {
          ciphers.pop();
        }

        const clonedOptions = { ...options };

        IGNORED_FIELD_NAMES.forEach((name) => {
          delete clonedOptions[name];
        });

        const tlsCipherPairs = [
          ["TLSv1", "TLSv1.2"],
          ["TLSv1", "TLSv1.3"],
          ["TLSv1.1", "TLSv1.2"],
          ["TLSv1.1", "TLSv1.3"],
          ["TLSv1.2", "TLSv1.2"],
          ["TLSv1.2", "TLSv1.3"],
          ["TLSv1.3", "TLSv1.3"],
        ];

        const tlsSettingsContradict =
          [
            clonedOptions.forceTlsV1,
            clonedOptions.forceTlsV1dot1,
            clonedOptions.forceTlsV1dot2,
          ].filter(Boolean).length && !clonedOptions.legacyTlsSpoof;

        if (tlsSettingsContradict) {
          throw new Error("legacyTlsSpoof required to force tls version");
        }

        if (clonedOptions.legacyTlsSpoof) {
          tlsCipherPairs.push(
            ...[
              ["TLSv1", "TLSv1"],
              ["TLSv1", "TLSv1.1"],
            ]
          );

          if (clonedOptions.forceTlsV1) {
            tlsCipherPairs.splice(0, tlsCipherPairs.length);
            tlsCipherPairs.push(["TLSv1", "TLSv1"]);
          }

          if (clonedOptions.forceTlsV1dot1) {
            tlsCipherPairs.splice(0, tlsCipherPairs.length);
            tlsCipherPairs.push(["TLSv1.1", "TLSv1.1"]);
          }

          if (clonedOptions.forceTlsV1dot2) {
            tlsCipherPairs.splice(0, tlsCipherPairs.length);
            tlsCipherPairs.push(["TLSv1.2", "TLSv1.2"]);
          }
        }

        if (clonedOptions.tls) {
          const { tls: version } = clonedOptions;

          tlsCipherPairs.splice(0, tlsCipherPairs.length);
          tlsCipherPairs.push([version, version]);
        }

        const [minTlsVersion, maxTlsVersion] =
          tlsCipherPairs[randint(0, tlsCipherPairs.length - 1)];

        return tls.connect(port.length ? Number(port) : HTTPS_PORT, hostname, {
          servername: host,
          ALPNProtocols: ["h2"],
          ciphers: ciphers.join(":").toUpperCase(),
          requestCert: true,
          rejectUnauthorized: false,
          secureContext: tls.createSecureContext({
            minVersion: minTlsVersion,
            maxVersion: maxTlsVersion,
          }),
          ...clonedOptions.tlsConnectOverrides,
        });
      },
    };
  };
}

module.exports = {
  AntiFingerprintClientSessionOptions,
};

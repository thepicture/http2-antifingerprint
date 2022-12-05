const tls = require("node:tls");

const { randint } = require("../randint.js");

const PORT = 443;
class AntiFingerprintClientSessionOptions {
  get = () => ({
    settings: {
      headerTableSize: randint(0, 2 ** 16 - 1),
      enablePush: !!randint(0, 1),
      initialWindowSize: randint(0, 2 ** 16 - 1),
      maxFrameSize: randint(16384, 2 ** 24 - 1),
      maxConcurrentStreams: randint(0, 2 ** 16 - 1),
      maxHeaderListSize: randint(0, 2 ** 16 - 1),
      enableConnectProtocol: !!randint(0, 1),
    },
    createConnection: (url) => {
      const ciphers = tls.getCiphers();
      ciphers.sort(() => (!!randint(0, 1) ? 1 : -1));
      for (let i = 0; i < randint(0, 2); i++) {
        ciphers.pop();
      }
      return tls.connect(PORT, url.host, {
        ALPNProtocols: ["h2"],
        ciphers: ciphers.join(":").toUpperCase(),
      });
    },
  });
}

module.exports = {
  AntiFingerprintClientSessionOptions,
};

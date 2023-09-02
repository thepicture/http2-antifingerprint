const http2antifingerprint = require("./src/http2-antifingerprint");
const {
  AntiFingerprintClientSessionOptions,
} = require("./src/options/AntiFingerprintClientSessionOptions");

module.exports = {
  http2antifingerprint,
  AntiFingerprintClientSessionOptions,
  connect: http2antifingerprint.connect,
};

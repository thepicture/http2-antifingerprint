const { readFileSync } = require("node:fs");
const { constants, createSecureServer } = require("node:http2");

let server;

(async () => {
  server = createSecureServer({
    key: readFileSync("localhost-privkey.pem"),
    cert: readFileSync("localhost-cert.pem"),
  })
    .on("stream", (stream) => {
      stream.respond({
        [constants.HTTP2_HEADER_CONTENT_TYPE]: "text/html; charset=utf-8",
        [constants.HTTP2_HEADER_STATUS]: constants.HTTP_STATUS_OK,
      });
      stream.end("<html></html>");
    })
    .listen(Number(process.argv.at(-1)), () => {
      process.stdout.write("listening");
    });
})();

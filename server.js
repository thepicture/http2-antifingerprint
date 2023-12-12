"use strict";

const { readFileSync } = require("node:fs");
const { createSecureServer } = require("node:http2");

const PORT = 3000;

createSecureServer({
  key: readFileSync("localhost-privkey.pem"),
  cert: readFileSync("localhost-cert.pem"),
})
  .on("request", (request, response) => {
    if (request.headers[":path"] === "/tls") {
      response.end(request.stream.session.socket._handle.getCipher().version);

      return;
    }

    response.end("<html></html>");
  })
  .listen(PORT, () => process.stdout.write("ready"));

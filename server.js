"use strict";

const { readFileSync } = require("node:fs");
const { createSecureServer } = require("node:http2");

const PORT = 3000;

createSecureServer({
  key: readFileSync("localhost-privkey.pem"),
  cert: readFileSync("localhost-cert.pem"),
})
  .on("stream", (stream) => {
    stream.respond({
      "content-type": "text/html; charset=utf-8",
      ":status": 200,
    });
    stream.end("<html></html>");
  })
  .listen(PORT, () => process.stdout.write("ready"));

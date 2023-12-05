import { Http2Server } from "node:http2";
import { constants, createSecureServer } from "node:http2";
import { readFileSync } from "node:fs";

let server: Http2Server;

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

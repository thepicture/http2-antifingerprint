"use strict";

import { constants } from "node:http2";

module.exports = {
  order: {
    chrome: {
      post: {
        header: {
          order: {
            pseudo: [
              constants.HTTP2_HEADER_METHOD,
              constants.HTTP2_HEADER_AUTHORITY,
              constants.HTTP2_HEADER_SCHEME,
              constants.HTTP2_HEADER_PATH,
            ],
            http: [
              "content-length",
              "pragma",
              "cache-control",
              "sec-ch-ua",
              "sec-ch-ua-platform",
              "accept-language",
              "sec-ch-ua-mobile",
              "user-agent",
              "content-type",
              "accept",
              "origin",
              "sec-fetch-site",
              "sec-fetch-mode",
              "sec-fetch-dest",
              "referer",
              "accept-encoding",
            ],
          },
        },
      },
      get: {
        header: {
          order: {
            pseudo: [
              constants.HTTP2_HEADER_METHOD,
              constants.HTTP2_HEADER_AUTHORITY,
              constants.HTTP2_HEADER_SCHEME,
              constants.HTTP2_HEADER_PATH,
            ],
            http: [
              "pragma",
              "cache-control",
              "sec-ch-ua",
              "sec-ch-ua-mobile",
              "sec-ch-ua-platform",
              "accept-language",
              "upgrade-insecure-requests",
              "user-agent",
              "accept",
              "sec-fetch-site",
              "sec-fetch-mode",
              "sec-fetch-user",
              "sec-fetch-dest",
              "referer",
              "accept-encoding",
            ],
          },
        },
      },
    },
  },
};

module.exports = {
  order: {
    chrome: {
      post: {
        header: {
          order: {
            pseudo: [":method", ":authority", ":scheme", ":path"],
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
            pseudo: [":method", ":authority", ":scheme", ":path"],
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

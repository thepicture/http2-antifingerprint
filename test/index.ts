import pem, { CertificateCreationResult } from "pem";

import assert from "node:assert/strict";
import { ClientHttp2Session, ClientHttp2Stream, Http2Server } from "node:http2";
import { constants, createSecureServer } from "node:http2";
import { describe, it, beforeEach, afterEach } from "node:test";

import http2antifingerprint from "..";

process.on("uncaughtException", process.exit);

const listener = () => {};
const { keys: ObjectKeys } = Object;

describe("client instantiation", () => {
  it("should instantiate client", async () => {
    const expected = true;

    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener
    );
    const actual = "alpnProtocol" in client;
    client.destroy();

    assert.strictEqual(actual, expected);
  });
});

describe("connection", () => {
  let server: Http2Server;
  let clientKey: string;
  let certificate: string;

  beforeEach(async () => {
    ({ clientKey, certificate } = await new Promise<CertificateCreationResult>(
      (resolve) => {
        pem.createCertificate(
          { selfSigned: true },
          (_, certificate: CertificateCreationResult) => resolve(certificate)
        );
      }
    ));

    server = createSecureServer({ key: clientKey, cert: certificate })
      .on("stream", (stream) => {
        stream.respond({
          [constants.HTTP2_HEADER_CONTENT_TYPE]: "text/html; charset=utf-8",
          [constants.HTTP2_HEADER_STATUS]: constants.HTTP_STATUS_OK,
        });
        stream.end("<html></html>");
      })
      .listen(3000);
  });

  afterEach(() => {
    server.close();
  });

  it("should receive body", async (_, done) => {
    const expected = "<body></body>";

    const client: ClientHttp2Session = await http2antifingerprint.connect(
      "https://localhost:3000",
      {},
      { ca: certificate }
    );
    const request: ClientHttp2Stream = client.request({
      [constants.HTTP2_HEADER_PATH]: "/",
    });
    request.setEncoding("utf8");

    let actual = "";
    request.on("data", (chunk: string) => {
      actual += chunk;
    });
    request.on("end", () => {
      client.close();

      assert.strictEqual(actual, expected);
      done();
    });
    request.end();
  });
});

describe("request", () => {
  it("should fallback to client options on no options", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        preferChromeHeaderOrder: true,
      }
    );

    const actual = () => client.request("/api");

    try {
      assert.doesNotThrow(actual);
    } finally {
      client.destroy();
    }
  });

  it("should throw error in request with strict mode without options", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        preferChromeHeaderOrder: true,
        strictMode: true,
      }
    );

    const actual = () => client.request("/api");

    try {
      assert.throws(actual);
    } finally {
      client.destroy();
    }
  });

  it("should not throw error in request with strict mode with options", async () => {
    const options = {
      preferChromeHeaderOrder: true,
      strictMode: true,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const actual = () => client.request("/api", http2options, options);

    try {
      assert.doesNotThrow(actual);
    } finally {
      client.destroy();
    }
  });

  it("should not throw error in request without strict mode with options", async () => {
    const options = {
      preferChromeHeaderOrder: true,
      strictMode: true,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const actual = () => client.request("/api", http2options, options);

    try {
      assert.doesNotThrow(actual);
    } finally {
      client.destroy();
    }
  });

  it("should throw after impossible merged options from connect and request contexts", async () => {
    const options = {
      reorderHeaders: true,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const actual = () =>
      client.request("/api", http2options, {
        preferChromeHeaderOrder: true,
      });

    try {
      assert.throws(actual);
    } finally {
      client.destroy();
    }
  });

  it("should throw after impossible merged options from undefined connect and request contexts", async () => {
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener
    );

    const actual = () =>
      client.request("/api", http2options, {
        preferChromeHeaderOrder: true,
      });

    try {
      assert.throws(actual);
    } finally {
      client.destroy();
    }
  });

  it("should throw after impossible merged options from connect and undefined request contexts", async () => {
    const options = {
      reorderHeaders: true,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        preferChromeHeaderOrder: true,
      }
    );

    const actual = () => client.request("/api", http2options, options);

    try {
      assert.throws(actual);
    } finally {
      client.destroy();
    }
  });

  it("should override tls connect options", async () => {
    // \x02h2\bhttp/1.1\bspdy/3.1
    const expected = [
      2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49, 8, 115, 112, 100, 121,
      47, 51, 46, 49,
    ];
    const options = {
      tlsConnectOverrides: {
        ALPNProtocols: ["h2", "http/1.1", "spdy/3.1"],
      },
    };
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const {
      session: {
        socket: {
          _tlsOptions: { ALPNProtocols: actual },
        },
      },
    } = await client.request("/api");

    assert.deepStrictEqual(Array.from(actual), expected);
  });

  it("should access options applied", async () => {
    const options = {
      tlsConnectOverrides: {
        ALPNProtocols: ["h2", "http/1.1", "spdy/3.1"],
      },
    };
    const expected = options;
    const { _http2antifingerprintOptions: actual } =
      await http2antifingerprint.connect(
        "https://example.com",
        listener,
        options
      );

    assert.deepStrictEqual(actual, expected);
  });

  it("should access listener applied", async () => {
    const expected = listener;
    const options = {};
    const { _http2antifingerprintListener: actual } =
      await http2antifingerprint.connect(
        "https://example.com",
        listener,
        options
      );

    assert.deepStrictEqual(actual, expected);
  });

  it("should work with negotiation spoof", async () => {
    const expected = true;
    const options = {
      negotiationSpoof: true,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const {
      _http2antifingerprintSessionOptions: {
        negotiationSpoof: actualNegotiationSpoof,
      },
    } = client;
    const actualFunctionCall = () =>
      client.request("/api", http2options, options);

    try {
      assert.doesNotThrow(actualFunctionCall);
      assert.strictEqual(actualNegotiationSpoof, expected);
    } finally {
      client.destroy();
    }
  });

  it("should work with negotiation spoof", async () => {
    const expected = true;
    const options = {
      curveSpoof: true,
    };
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const {
      _http2antifingerprintSessionOptions: { curveSpoof: actualCurveSpoof },
    } = client;

    try {
      assert.strictEqual(actualCurveSpoof, expected);
    } finally {
      client.destroy();
    }
  });

  it("should allow to spoof secure options", async () => {
    const expected = true;
    const options = {
      spoofSecureOptions: true,
    };

    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const {
      _http2antifingerprintSessionOptions: {
        spoofSecureOptions: actualSpoofSecureOptions,
      },
    } = client;

    try {
      assert.strictEqual(actualSpoofSecureOptions, expected);
    } finally {
      client.destroy();
    }
  });

  it("should send headers with shuffled order and with static pseudo-header order", async () => {
    const expectedPseudoHeaderOrder = [
      ":method",
      ":authority",
      ":scheme",
      ":path",
    ];
    const notExpectedHeaderOrder = [
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect("https://example.com");

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          ":method": "GET",
          ":authority": "example.com",
          ":scheme": "https",
          ":path": "/api",
          "user-agent": "node",
          "accept-encoding": "gzip, deflate, br",
          "accept-language": "en-US",
        },
        {},
        {
          reorderPseudoHeaders: false,
          banOriginalHeaderOrder: true,
        }
      );

      assert.deepStrictEqual(
        ObjectKeys(actual).slice(0, 4),
        expectedPseudoHeaderOrder
      );
      assert.notDeepStrictEqual(
        ObjectKeys(actual).slice(4),
        notExpectedHeaderOrder
      );
    }

    try {
      client.destroy();
    } finally {
    }
  });

  it("should send headers with shuffled pseudo-header order and with static header order", async () => {
    const notExpectedPseudoHeaderOrder = [
      ":method",
      ":authority",
      ":scheme",
      ":path",
    ];
    const expectedHeaderOrder = [
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect("https://example.com");

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          ":method": "GET",
          ":authority": "example.com",
          ":scheme": "https",
          ":path": "/api",
          "user-agent": "node",
          "accept-encoding": "gzip, deflate, br",
          "accept-language": "en-US",
        },
        {},
        {
          reorderHeaders: false,
          banOriginalPseudoHeaderOrder: true,
        }
      );

      assert.notDeepStrictEqual(
        ObjectKeys(actual).slice(0, 4),
        notExpectedPseudoHeaderOrder
      );
      assert.deepStrictEqual(ObjectKeys(actual).slice(4), expectedHeaderOrder);
    }

    try {
      client.destroy();
    } finally {
    }
  });

  it("should send headers with shuffled pseudo-header order and with shuffled header order", async () => {
    const notExpectedHeaderOrder = [
      ":method",
      ":authority",
      ":scheme",
      ":path",
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect("https://example.com");

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          ":method": "GET",
          ":authority": "example.com",
          ":scheme": "https",
          ":path": "/api",
          "user-agent": "node",
          "accept-encoding": "gzip, deflate, br",
          "accept-language": "en-US",
        },
        {},
        {
          banOriginalPseudoHeaderOrder: true,
          banOriginalHeaderOrder: true,
        }
      );

      assert.notDeepStrictEqual(ObjectKeys(actual), notExpectedHeaderOrder);
    }

    try {
      client.destroy();
    } finally {
    }
  });

  it("should send static pseudo- and original headers", async () => {
    const expected = [
      ":method",
      ":authority",
      ":scheme",
      ":path",
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect("https://example.com");

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          ":method": "GET",
          ":authority": "example.com",
          ":scheme": "https",
          ":path": "/api",
          "user-agent": "node",
          "accept-encoding": "gzip, deflate, br",
          "accept-language": "en-US",
        },
        {},
        {
          reorderHeaders: false,
          reorderPseudoHeaders: false,
        }
      );

      assert.deepStrictEqual(ObjectKeys(actual), expected);
    }

    try {
      client.destroy();
    } finally {
    }
  });

  it("should spoof cipher preferences", async () => {
    const expected = true;
    const options = {
      spoofHonorCipherOrder: true,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      options
    );

    const {
      _http2antifingerprintSessionOptions: { spoofHonorCipherOrder: actual },
    } = client;
    const actualFunctionCall = () =>
      client.request("/api", http2options, options);

    try {
      assert.doesNotThrow(actualFunctionCall);
      assert.strictEqual(actual, expected);
    } finally {
      client.destroy();
    }
  });

  it("should work with unauthenticated proxy", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        scheme: "http",
        host: "proxy.com",
        port: 80,
      }
    );

    const actual = () => client.request("/api", {}, {});

    try {
      assert.doesNotThrow(actual);
      assert.ok(client._http2antifingerprintOptions);
      assert.ok(client._http2antifingerprintOptions.host);
      assert.ok(client._http2antifingerprintOptions.port);
      assert.strictEqual(client._http2antifingerprintOptions.user, undefined);
      assert.strictEqual(
        client._http2antifingerprintOptions.password,
        undefined
      );
      assert.ok(client._http2antifingerprintListener);
      assert.ok(client._http2antifingerprintSessionOptions);
    } finally {
      client.destroy();
    }
  });

  it("should work with authenticated proxy", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        scheme: "http",
        host: "proxy.com",
        user: "",
        password: "",
        port: 80,
      }
    );

    const actual = () => client.request("/api", {}, {});

    try {
      assert.doesNotThrow(actual);
      assert.ok(client._http2antifingerprintOptions);
      assert.ok(client._http2antifingerprintOptions.host);
      assert.ok(client._http2antifingerprintOptions.port);
      assert.strictEqual(client._http2antifingerprintOptions.user, "");
      assert.strictEqual(client._http2antifingerprintOptions.password, "");
      assert.ok(client._http2antifingerprintListener);
      assert.ok(client._http2antifingerprintSessionOptions);
    } finally {
      client.destroy();
    }
  });

  it("should throw with authenticated proxy and contradiction options", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        scheme: "http",
        host: "proxy.com",
        user: "",
        password: "",
        port: 80,
        strictMode: true,
        preferChromeHeaderOrder: true,
        reorderHeaders: true,
      }
    );

    const actual = () => client.request("/api", {}, {});

    try {
      assert.throws(actual);
    } finally {
      client.destroy();
    }
  });

  it("should work with authenticated proxy and semantically correct options", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        scheme: "http",
        host: "proxy.com",
        user: "",
        password: "",
        port: 80,
        strictMode: true,
        preferChromeHeaderOrder: true,
        reorderHeaders: false,
      }
    );

    const actual = () => client.request("/api", {}, {});

    try {
      assert.doesNotThrow(actual);
      assert.ok(client._http2antifingerprintOptions);
      assert.ok(client._http2antifingerprintOptions.host);
      assert.ok(client._http2antifingerprintOptions.port);
      assert.strictEqual(client._http2antifingerprintOptions.user, "");
      assert.strictEqual(client._http2antifingerprintOptions.password, "");
      assert.ok(client._http2antifingerprintListener);
      assert.ok(client._http2antifingerprintSessionOptions);
    } finally {
      client.destroy();
    }
  });

  it("should throw with authenticated proxy and contradiction options in request", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        scheme: "http",
        host: "proxy.com",
        user: "",
        password: "",
        port: 80,
        strictMode: true,
      }
    );

    const actual = () =>
      client.request(
        "/api",
        {},
        {
          preferChromeHeaderOrder: true,
          reorderHeaders: true,
        }
      );

    try {
      assert.throws(actual);
    } finally {
      client.destroy();
    }
  });

  it("should work with authenticated proxy and semantically correct options", async () => {
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        scheme: "http",
        host: "proxy.com",
        user: "",
        password: "",
        port: 80,
        strictMode: true,
      }
    );

    const actual = () =>
      client.request(
        "/api",
        {},
        {
          preferChromeHeaderOrder: true,
          reorderHeaders: false,
        }
      );

    try {
      assert.doesNotThrow(actual);
      assert.ok(client._http2antifingerprintOptions);
      assert.ok(client._http2antifingerprintOptions.host);
      assert.ok(client._http2antifingerprintOptions.port);
      assert.strictEqual(client._http2antifingerprintOptions.user, "");
      assert.strictEqual(client._http2antifingerprintOptions.password, "");
      assert.ok(client._http2antifingerprintListener);
      assert.ok(client._http2antifingerprintSessionOptions);
    } finally {
      client.destroy();
    }
  });

  it("should make seed generation idempotent", async () => {
    const expected1 = [
      {
        headerTableSize: 0,
        enablePush: true,
        initialWindowSize: 595786089,
        maxFrameSize: 23602621357,
        maxConcurrentStreams: -496240228,
        maxHeaderListSize: -628768293,
        enableConnectProtocol: true,
      },
    ];
    const expected2 = [
      {
        headerTableSize: 551400888,
        enablePush: true,
        initialWindowSize: 92287800,
        maxFrameSize: -126913421755,
        maxConcurrentStreams: -628768293,
        maxHeaderListSize: -183510957,
        enableConnectProtocol: true,
      },
    ];
    const client1 = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        seed: 0,
      }
    );

    client1.request("/");
    client1.request("/");
    client1.request("/");

    let actual1 = client1._http2antifingerprint.seedHistory;

    client1.request("/");
    client1.request("/");
    client1.request("/");

    let actual2 = client1._http2antifingerprint.seedHistory;

    assert.deepEqual(actual1, expected1);
    assert.deepEqual(actual2, expected1);

    const client2 = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        seed: 1,
      }
    );

    client2.request("/");
    client2.request("/");
    client2.request("/");

    let actual3 = client2._http2antifingerprint.seedHistory;

    client2.request("/");
    client2.request("/");
    client2.request("/");

    let actual4 = client2._http2antifingerprint.seedHistory;

    const actual5 = client1._http2antifingerprint.seedHistory;
    const actual6 = client2._http2antifingerprint.seedHistory;

    assert.deepEqual(actual3, expected2);
    assert.deepEqual(actual4, expected2);
    assert.notDeepStrictEqual(actual5, actual6);
  });
});

describe("non-standart port scope", () => {
  let server: Http2Server;
  let clientKey: string;
  let certificate: string;

  beforeEach(async () => {
    ({ clientKey, certificate } = await new Promise<CertificateCreationResult>(
      (resolve) => {
        pem.createCertificate(
          { selfSigned: true },
          (_, certificate: CertificateCreationResult) => resolve(certificate)
        );
      }
    ));

    server = createSecureServer({ key: clientKey, cert: certificate })
      .on("stream", (stream) => {
        stream.respond({
          [constants.HTTP2_HEADER_CONTENT_TYPE]: "text/html; charset=utf-8",
          [constants.HTTP2_HEADER_STATUS]: constants.HTTP_STATUS_OK,
        });
        stream.end("<html></html>");
      })
      .listen(3000);
  });

  afterEach(() => {
    server.close();
  });

  it("should work with non-standard port", async (_, done) => {
    const expected = "<html></html>";
    const options = {};
    const http2options = {};
    const client = await http2antifingerprint.connect(
      "https://non-standard.com:666"
    );

    let actual = "";

    const request = client.request(
      { [constants.HTTP2_HEADER_PATH]: "/" },
      http2options,
      options
    );
    request.setEncoding("utf8");

    request.on("error", assert.fail);

    request.on("data", (chunk: string) => {
      actual += chunk;
    });

    request.on("end", () => {
      assert.strictEqual(actual, expected);

      client.destroy();

      done();
    });

    request.end();
  });

  it("should set cert option", async () => {
    const expected = "stub";
    const client = await http2antifingerprint.connect(
      "https://example.com",
      listener,
      {
        ca: "stub",
      }
    );

    let actual = client._http2antifingerprintOptions.ca;

    assert.strictEqual(actual, expected);
  });
});

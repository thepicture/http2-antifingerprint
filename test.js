const { constants } = require("node:http2");
const { readFileSync } = require("node:fs");
const assert = require("node:assert/strict");
const { it, describe, before, after } = require("node:test");
const { spawn, ChildProcess } = require("node:child_process");
const http2antifingerprint = require(".");

const PORT = 3000;
const NOOP = new Function();
const MOCK_URL = `https://localhost:${PORT}`;
const ca = readFileSync("localhost-cert.pem");

/**
 * @type {ChildProcess}
 */
let worker;

describe(() => {
  before(async () => {
    await new Promise((resolve) => {
      worker = spawn("node", ["./server.js"]);
      worker.stdout.on("data", resolve);
    });
  });

  after(async () => {
    await new Promise((r) => setTimeout(r, 1000));
    worker.kill();
  });

  it("should instantiate client", async () => {
    const expected = true;

    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      ca,
    });
    const actual = "alpnProtocol" in client;

    assert.strictEqual(actual, expected);
  });

  it("should fallback to client options on no options", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      preferChromeHeaderOrder: true,
      ca: readFileSync("localhost-cert.pem"),
    });

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" });

    assert.doesNotThrow(actual);
  });

  it("should throw error in request with strict mode without options", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      preferChromeHeaderOrder: true,
      strictMode: true,
      ca,
    });

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" });

    assert.throws(actual);
  });

  it("should not throw error in request with strict mode with options", async () => {
    const options = {
      preferChromeHeaderOrder: true,
      strictMode: true,
      ca,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const actual = () =>
      client.request(
        { [constants.HTTP2_HEADER_PATH]: "/api" },
        http2options,
        options
      );

    assert.doesNotThrow(actual);
  });

  it("should not throw error in request without strict mode with options", async () => {
    const options = {
      preferChromeHeaderOrder: true,
      strictMode: true,
      ca,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const actual = () =>
      client.request(
        { [constants.HTTP2_HEADER_PATH]: "/api" },
        http2options,
        options
      );

    assert.doesNotThrow(actual);
  });

  it("should throw after impossible merged options from connect and request contexts", async () => {
    const options = {
      reorderHeaders: true,
      ca,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" }, http2options, {
        preferChromeHeaderOrder: true,
      });

    assert.throws(actual);
  });

  it("should throw after impossible merged options from undefined connect and request contexts", async () => {
    const http2options = {};
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP);

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" }, http2options, {
        preferChromeHeaderOrder: true,
        ca,
      });

    assert.throws(actual);
  });

  it("should throw after impossible merged options from connect and undefined request contexts", async () => {
    const options = {
      reorderHeaders: true,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      preferChromeHeaderOrder: true,
      ca,
    });

    const actual = () =>
      client.request(
        { [constants.HTTP2_HEADER_PATH]: "/api" },
        http2options,
        options
      );

    assert.throws(actual);
  });

  it("should override tls connect options", async () => {
    const expected = [...Buffer.from("\x02h2\bhttp/1.1\bspdy/3.1")];
    const options = {
      tlsConnectOverrides: {
        ALPNProtocols: ["h2", "http/1.1", "spdy/3.1"],
      },
      ca,
    };
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const {
      session: {
        socket: {
          _tlsOptions: { ALPNProtocols: actual },
        },
      },
    } = await client.request({ [constants.HTTP2_HEADER_PATH]: "/api" });

    assert.deepStrictEqual(Array.from(actual), expected);
  });

  it("should access options applied", async () => {
    const options = {
      tlsConnectOverrides: {
        ALPNProtocols: ["h2", "http/1.1", "spdy/3.1"],
      },
      ca,
    };
    const expected = options;
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);
    const { _http2antifingerprintOptions: actual } = client;

    assert.deepStrictEqual(actual, expected);
  });

  it("should access listener applied", async () => {
    const expected = NOOP;
    const options = { ca };
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);
    const { _http2antifingerprintListener: actual } = client;

    assert.deepStrictEqual(actual, expected);
  });

  it("should work with negotiation spoof", async () => {
    const expected = true;
    const options = {
      negotiationSpoof: true,
      ca,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const {
      _http2antifingerprintSessionOptions: {
        negotiationSpoof: actualNegotiationSpoof,
      },
    } = client;
    const actualFunctionCall = () =>
      client.request(
        { [constants.HTTP2_HEADER_PATH]: "/api" },
        http2options,
        options
      );

    assert.doesNotThrow(actualFunctionCall);
    assert.strictEqual(actualNegotiationSpoof, expected);
  });

  it("should work with negotiation spoof", async () => {
    const expected = true;
    const options = {
      curveSpoof: true,
      ca,
    };
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const {
      _http2antifingerprintSessionOptions: { curveSpoof: actualCurveSpoof },
    } = client;

    assert.strictEqual(actualCurveSpoof, expected);
  });

  it("should allow to spoof secure options", async () => {
    const expected = true;
    const options = {
      spoofSecureOptions: true,
      ca,
    };

    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const {
      _http2antifingerprintSessionOptions: {
        spoofSecureOptions: actualSpoofSecureOptions,
      },
    } = client;

    assert.strictEqual(actualSpoofSecureOptions, expected);
  });

  it("should send headers with shuffled order and with static pseudo-header order", async () => {
    const expectedPseudoHeaderOrder = [
      constants.HTTP2_HEADER_METHOD,
      constants.HTTP2_HEADER_AUTHORITY,
      constants.HTTP2_HEADER_SCHEME,
      constants.HTTP2_HEADER_PATH,
    ];
    const notExpectedHeaderOrder = [
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, { ca });

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          [constants.HTTP2_HEADER_METHOD]: "GET",
          [constants.HTTP2_HEADER_AUTHORITY]: "example.com",
          [constants.HTTP2_HEADER_SCHEME]: "https",
          [constants.HTTP2_HEADER_PATH]: "/api",
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
        Object.keys(actual).slice(0, 4),
        expectedPseudoHeaderOrder
      );
      assert.notDeepStrictEqual(
        Object.keys(actual).slice(4),
        notExpectedHeaderOrder
      );
    }
  });

  it("should send headers with shuffled pseudo-header order and with static header order", async () => {
    const notExpectedPseudoHeaderOrder = [
      constants.HTTP2_HEADER_METHOD,
      constants.HTTP2_HEADER_AUTHORITY,
      constants.HTTP2_HEADER_SCHEME,
      constants.HTTP2_HEADER_PATH,
    ];
    const expectedHeaderOrder = [
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, { ca });

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          [constants.HTTP2_HEADER_METHOD]: "GET",
          [constants.HTTP2_HEADER_AUTHORITY]: "example.com",
          [constants.HTTP2_HEADER_SCHEME]: "https",
          [constants.HTTP2_HEADER_PATH]: "/api",
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
        Object.keys(actual).slice(0, 4),
        notExpectedPseudoHeaderOrder
      );
      assert.deepStrictEqual(Object.keys(actual).slice(4), expectedHeaderOrder);
    }
  });

  it("should send headers with shuffled pseudo-header order and with shuffled header order", async () => {
    const notExpectedHeaderOrder = [
      constants.HTTP2_HEADER_METHOD,
      constants.HTTP2_HEADER_AUTHORITY,
      constants.HTTP2_HEADER_SCHEME,
      constants.HTTP2_HEADER_PATH,
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, { ca });

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          [constants.HTTP2_HEADER_METHOD]: "GET",
          [constants.HTTP2_HEADER_AUTHORITY]: "example.com",
          [constants.HTTP2_HEADER_SCHEME]: "https",
          [constants.HTTP2_HEADER_PATH]: "/api",
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

      assert.notDeepStrictEqual(Object.keys(actual), notExpectedHeaderOrder);
    }
  });

  it("should send static pseudo- and original headers", async () => {
    const expected = [
      constants.HTTP2_HEADER_METHOD,
      constants.HTTP2_HEADER_AUTHORITY,
      constants.HTTP2_HEADER_SCHEME,
      constants.HTTP2_HEADER_PATH,
      "user-agent",
      "accept-encoding",
      "accept-language",
    ];
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, { ca });

    for (let i = 0; i < 1024; i++) {
      const { sentHeaders: actual } = await client.request(
        {
          [constants.HTTP2_HEADER_METHOD]: "GET",
          [constants.HTTP2_HEADER_AUTHORITY]: "example.com",
          [constants.HTTP2_HEADER_SCHEME]: "https",
          [constants.HTTP2_HEADER_PATH]: "/api",
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

      assert.deepStrictEqual(Object.keys(actual), expected);
    }
  });

  it("should spoof cipher preferences", async () => {
    const expected = true;
    const options = {
      spoofHonorCipherOrder: true,
      ca,
    };
    const http2options = {};
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, options);

    const {
      _http2antifingerprintSessionOptions: { spoofHonorCipherOrder: actual },
    } = client;
    const actualFunctionCall = () =>
      client.request(
        { [constants.HTTP2_HEADER_PATH]: "/api" },
        http2options,
        options
      );

    assert.doesNotThrow(actualFunctionCall);
    assert.strictEqual(actual, expected);
  });

  it("should work with unauthenticated proxy", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      scheme: "http",
      host: "proxy.com",
      port: 80,
      ca,
    });

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" }, {}, {});

    assert.doesNotThrow(actual);
    assert.ok(client._http2antifingerprintOptions);
    assert.ok(client._http2antifingerprintOptions.host);
    assert.ok(client._http2antifingerprintOptions.port);
    assert.strictEqual(client._http2antifingerprintOptions.user, undefined);
    assert.strictEqual(client._http2antifingerprintOptions.password, undefined);
    assert.ok(client._http2antifingerprintListener);
    assert.ok(client._http2antifingerprintSessionOptions);
  });

  it("should work with authenticated proxy", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      scheme: "http",
      host: "proxy.com",
      user: "",
      password: "",
      port: 80,
      ca,
    });

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" }, {}, {});

    assert.doesNotThrow(actual);
    assert.ok(client._http2antifingerprintOptions);
    assert.ok(client._http2antifingerprintOptions.host);
    assert.ok(client._http2antifingerprintOptions.port);
    assert.strictEqual(client._http2antifingerprintOptions.user, "");
    assert.strictEqual(client._http2antifingerprintOptions.password, "");
    assert.ok(client._http2antifingerprintListener);
    assert.ok(client._http2antifingerprintSessionOptions);
  });

  it("should throw with authenticated proxy and contradiction options", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      scheme: "http",
      host: "proxy.com",
      user: "",
      password: "",
      port: 80,
      strictMode: true,
      preferChromeHeaderOrder: true,
      reorderHeaders: true,
      ca,
    });

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" }, {}, {});

    assert.throws(actual);
  });

  it("should work with authenticated proxy and semantically correct options", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      scheme: "http",
      host: "proxy.com",
      user: "",
      password: "",
      port: 80,
      strictMode: true,
      preferChromeHeaderOrder: true,
      reorderHeaders: false,
      ca,
    });

    const actual = () =>
      client.request({ [constants.HTTP2_HEADER_PATH]: "/api" }, {}, {});

    assert.doesNotThrow(actual);
    assert.ok(client._http2antifingerprintOptions);
    assert.ok(client._http2antifingerprintOptions.host);
    assert.ok(client._http2antifingerprintOptions.port);
    assert.strictEqual(client._http2antifingerprintOptions.user, "");
    assert.strictEqual(client._http2antifingerprintOptions.password, "");
    assert.ok(client._http2antifingerprintListener);
    assert.ok(client._http2antifingerprintSessionOptions);
  });

  it("should throw with authenticated proxy and contradiction options in request", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      scheme: "http",
      host: "proxy.com",
      user: "",
      password: "",
      port: 80,
      strictMode: true,
      ca,
    });

    const actual = () =>
      client.request(
        { [constants.HTTP2_HEADER_PATH]: "/api" },
        {},
        {
          preferChromeHeaderOrder: true,
          reorderHeaders: true,
        }
      );

    assert.throws(actual);
  });

  it("should work with authenticated proxy and semantically correct options", async () => {
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      scheme: "http",
      host: "proxy.com",
      user: "",
      password: "",
      port: 80,
      strictMode: true,
      ca,
    });

    const actual = () =>
      client.request(
        { [constants.HTTP2_HEADER_PATH]: "/api" },
        {},
        {
          preferChromeHeaderOrder: true,
          reorderHeaders: false,
        }
      );

    assert.doesNotThrow(actual);
    assert.ok(client._http2antifingerprintOptions);
    assert.ok(client._http2antifingerprintOptions.host);
    assert.ok(client._http2antifingerprintOptions.port);
    assert.strictEqual(client._http2antifingerprintOptions.user, "");
    assert.strictEqual(client._http2antifingerprintOptions.password, "");
    assert.ok(client._http2antifingerprintListener);
    assert.ok(client._http2antifingerprintSessionOptions);
  });

  it("should make seed generation idempotent", async () => {
    const expected1 = [
      {
        headerTableSize: 55146,
        enablePush: false,
        initialWindowSize: 13019,
        maxFrameSize: 4969548,
        maxConcurrentStreams: 25520,
        maxHeaderListSize: 31419,
        enableConnectProtocol: true,
      },
    ];
    const expected2 = [
      {
        enableConnectProtocol: true,
        enablePush: true,
        headerTableSize: 55146,
        initialWindowSize: 61082,
        maxConcurrentStreams: 64582,
        maxFrameSize: 16166420,
        maxHeaderListSize: 65371,
      },
    ];
    const client1 = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      seed: 0,
      ca,
    });

    client1.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client1.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client1.request({ [constants.HTTP2_HEADER_PATH]: "/api" });

    const actual1 = client1._http2antifingerprint.seedHistory;

    client1.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client1.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client1.request({ [constants.HTTP2_HEADER_PATH]: "/api" });

    const actual2 = client1._http2antifingerprint.seedHistory;

    assert.deepEqual(actual1, expected1);
    assert.deepEqual(actual2, expected1);

    const client2 = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      seed: 1,
      ca,
    });

    client2.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client2.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client2.request({ [constants.HTTP2_HEADER_PATH]: "/api" });

    const actual3 = client2._http2antifingerprint.seedHistory;

    client2.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client2.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client2.request({ [constants.HTTP2_HEADER_PATH]: "/api" });

    const actual4 = client2._http2antifingerprint.seedHistory;
    const actual5 = client1._http2antifingerprint.seedHistory;
    const actual6 = client2._http2antifingerprint.seedHistory;

    assert.deepEqual(actual3, expected2);
    assert.deepEqual(actual4, expected2);
    assert.notDeepStrictEqual(actual5, actual6);
  });

  it("should randomize request frames on isRequestDependsOnSeed", async () => {
    const expected = [
      {
        enableConnectProtocol: true,
        enablePush: false,
        headerTableSize: 55146,
        initialWindowSize: 13019,
        maxConcurrentStreams: 25520,
        maxFrameSize: 4969548,
        maxHeaderListSize: 31419,
      },
      {
        enableConnectProtocol: true,
        enablePush: false,
        headerTableSize: 55146,
        initialWindowSize: 13019,
        maxConcurrentStreams: 25520,
        maxFrameSize: 4958007,
        maxHeaderListSize: 31419,
      },
      {
        enableConnectProtocol: true,
        enablePush: true,
        headerTableSize: 42219,
        initialWindowSize: 51336,
        maxConcurrentStreams: 58406,
        maxFrameSize: 14117540,
        maxHeaderListSize: 61082,
      },
      {
        enableConnectProtocol: true,
        enablePush: true,
        headerTableSize: 64582,
        initialWindowSize: 65508,
        maxConcurrentStreams: 63822,
        maxFrameSize: 16637374,
        maxHeaderListSize: 62016,
      },
    ];
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      seed: 0,
      isRequestDependsOnSeed: true,
      ca,
    });

    client.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    client.request({ [constants.HTTP2_HEADER_PATH]: "/api" });
    const actual = client._http2antifingerprint.seedHistory;

    assert.deepEqual(actual, expected);
  });

  it("should set cert option", async () => {
    const expected = "stub";
    const client = await http2antifingerprint.connect(MOCK_URL, NOOP, {
      ca: "stub",
    });

    const actual = client._http2antifingerprintOptions.ca;

    assert.strictEqual(actual, expected);
  });
});

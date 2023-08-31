import nock from "nock";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import http2antifingerprint from "..";

process.on("uncaughtException", process.exit);

nock("https://example.com").get("*").reply();
const listener = () => {};

describe("client instantiation", () => {
  it("should instantiate client", async () => {
    const expected = true;

    const actual = await http2antifingerprint.connect(
      "https://example.com",
      listener
    );

    actual.destroy();

    assert.strictEqual("alpnProtocol" in actual, expected);
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
});

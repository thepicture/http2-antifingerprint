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
});

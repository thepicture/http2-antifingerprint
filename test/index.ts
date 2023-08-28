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
    const client = await http2antifingerprint
      .connect("https://example.com", listener, {
        preferChromeHeaderOrder: true,
      })
      .catch(() => {});

    const actual = () => client.request("/api");

    try {
      assert.doesNotThrow(actual);
    } finally {
      client.destroy();
    }
  });
});

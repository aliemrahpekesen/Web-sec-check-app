import { describe, it, expect } from "vitest";
import { encodeScanId, decodeScanId } from "./scanid";

describe("scanid", () => {
  it("round-trips scan parameters", () => {
    const id = encodeScanId({ target: "https://ex.com/", host: "ex.com", profile: "STANDARD" });
    const p = decodeScanId(id);
    expect(p).toMatchObject({ target: "https://ex.com/", host: "ex.com", profile: "STANDARD" });
  });

  it("produces url-safe ids", () => {
    const id = encodeScanId({ target: "https://ex.com/?a=b&c=d", host: "ex.com", profile: "DEEP" });
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("returns null for malformed ids", () => {
    expect(decodeScanId("not-base64!!!")).toBeNull();
    expect(decodeScanId(Buffer.from('{"foo":1}').toString("base64url"))).toBeNull();
  });
});

import { describe, it, expect } from "vitest";
import { isPrivateIp, decodeIpv4Literal, assertPublicHost, SsrfError } from "./ssrf";

describe("isPrivateIp", () => {
  it("flags private/reserved IPv4", () => {
    for (const ip of [
      "127.0.0.1",
      "10.1.2.3",
      "192.168.0.1",
      "172.16.5.4",
      "169.254.169.254", // cloud metadata
      "100.64.0.1", // CGNAT
      "0.0.0.0",
      "255.255.255.255",
    ]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });

  it("allows public IPv4", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34"]) {
      expect(isPrivateIp(ip), ip).toBe(false);
    }
  });

  it("flags private/reserved IPv6 incl. mapped", () => {
    for (const ip of ["::1", "::", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1", "ff02::1"]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });

  it("allows public IPv6", () => {
    expect(isPrivateIp("2606:4700:4700::1111")).toBe(false);
  });

  it("treats non-IP strings as unsafe", () => {
    expect(isPrivateIp("example.com")).toBe(true);
  });
});

describe("decodeIpv4Literal", () => {
  it("decodes classic encoding bypasses to loopback", () => {
    for (const enc of ["2130706433", "0x7f000001", "0177.0.0.1", "127.1", "127.0.0.1"]) {
      expect(decodeIpv4Literal(enc), enc).toBe("127.0.0.1");
    }
  });

  it("returns null for hostnames", () => {
    expect(decodeIpv4Literal("example.com")).toBeNull();
    expect(decodeIpv4Literal("not.an.ip.addr")).toBeNull();
  });
});

describe("assertPublicHost", () => {
  it("rejects private hosts and encoded loopback without hitting DNS", async () => {
    for (const host of ["127.0.0.1", "10.0.0.5", "169.254.169.254", "2130706433", "0x7f000001", "::1", "[::1]"]) {
      await expect(assertPublicHost(host), host).rejects.toBeInstanceOf(SsrfError);
    }
  });

  it("allows public IP literals", async () => {
    await expect(assertPublicHost("8.8.8.8")).resolves.toBeUndefined();
    await expect(assertPublicHost("1.1.1.1")).resolves.toBeUndefined();
  });
});

import { RestrictedIssuerDnsTxt, locationInWhitelist } from ".";
import sample from "../../test/fixtures/sample.json";

const options = {
  network: "homestead",
};

describe("verify", () => {
  it("should fail pass for documents not issued from correct domains", async () => {
    const verificationFragment = await RestrictedIssuerDnsTxt.verify(sample as any, options);
    expect(verificationFragment).toMatchInlineSnapshot(`
      Object {
        "data": Array [
          Object {
            "isWhitelistedIssuer": false,
            "location": "demo.tradetrust.io",
            "status": "INVALID",
            "value": "0x6d71da10Ae0e5B73d0565E2De46741231Eb247C7",
          },
        ],
        "name": "OpenAttestationDidSignedDidIdentityProof",
        "status": "INVALID",
        "type": "ISSUER_IDENTITY",
      }
    `);
  });
});

describe("locationInWhitelist", () => {
  it("returns true for valid domains", () => {
    expect(locationInWhitelist("lol.gov.sg")).toBe(true);
    expect(locationInWhitelist("lol.lol.lol.gov.sg")).toBe(true);
    expect(locationInWhitelist("LOL.GOV.SG")).toBe(true);
    expect(locationInWhitelist("example.openattestation.com")).toBe(true);
  });

  it("returns false for invalid domains", () => {
    expect(locationInWhitelist("gov.sg")).toBe(false);
    expect(locationInWhitelist("gov.sg.fake.com")).toBe(false);
    expect(locationInWhitelist("fakegov.sg")).toBe(false);
    expect(locationInWhitelist("neopets.com")).toBe(false);
    expect(locationInWhitelist("gov.sg")).toBe(false);
    expect(locationInWhitelist("unicodeo.g𝗈v.sg")).toBe(false);
  });
});

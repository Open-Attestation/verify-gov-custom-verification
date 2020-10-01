import {
  Verifier,
  VerificationFragmentType,
  VerificationFragmentStatus,
  openAttestationDnsTxt,
} from "@govtechsg/oa-verify";
import { v2, v3, WrappedDocument } from "@govtechsg/open-attestation";

type VerifierType = Verifier<WrappedDocument<v2.OpenAttestationDocument> | WrappedDocument<v3.OpenAttestationDocument>>;
const name = "OpenAttestationDidSignedDidIdentityProof";
const type: VerificationFragmentType = "ISSUER_IDENTITY";

// Should never be used for now
const skip: VerifierType["skip"] = async () => {
  return {
    status: "SKIPPED",
    type,
    name,
    reason: {
      code: 1,
      codeString: "SKIPPED",
      message: `Verification is skipped`,
    },
  };
};

// Will run on ALL documents (ie all documents MUST have DNS-TXT)
// TODO extend with another verifier to deal with DNS-DID next time
const test: VerifierType["test"] = () => true;

const ALLOWED_SUBDOMAINS = [/.+\.gov\.sg$/i, /.+.openattestation.com$/i];

export const locationInWhitelist = (location?: string) => {
  if (!location) return false;
  return ALLOWED_SUBDOMAINS.some((regex) => regex.test(location));
};

export const validateRestrictedIssuer = ({
  status,
  location,
  value,
}: {
  status: string;
  location?: string;
  value?: string;
}) => {
  const isWhitelistedIssuer = locationInWhitelist(location);
  return {
    status: isWhitelistedIssuer ? status : "INVALID",
    location,
    value,
    isWhitelistedIssuer,
  };
};

const verify: VerifierType["verify"] = async (document, options) => {
  const dnsVerificationFragment = await openAttestationDnsTxt.verify(document, options);
  if (!dnsVerificationFragment.data) {
    return {
      name,
      type,
      status: "INVALID" as VerificationFragmentStatus,
      reason: {
        code: 0,
        codeString: "UNEXPECTED_ERROR",
        message: "data not found in verification fragment from openAttestationDnsTxt",
      },
    };
  }

  if (Array.isArray(dnsVerificationFragment.data)) {
    const validationResults = dnsVerificationFragment.data.map(validateRestrictedIssuer);
    return {
      name,
      type,
      data: validationResults,
      status:
        validationResults.length > 0 && validationResults.every((result) => result.status === "VALID")
          ? ("VALID" as VerificationFragmentStatus)
          : ("INVALID" as VerificationFragmentStatus),
    };
  }
  const data = validateRestrictedIssuer(dnsVerificationFragment.data);
  return {
    name,
    type,
    data,
    status: data.status as VerificationFragmentStatus,
  };
};

export const RestrictedIssuerDnsTxt: VerifierType = {
  skip,
  test,
  verify,
};

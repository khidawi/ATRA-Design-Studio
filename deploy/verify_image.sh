#!/bin/sh
# Checks that the ASTRA images for a release were built and signed by this repository's release workflow, before you run them.
#
#   ./verify_image.sh v1.4.0                    # both images, by tag
#   ./verify_image.sh v1.4.0 backend            # one image
#   ASTRA_REPO=owner/repo ./verify_image.sh v1.4.0     # a fork or a different repository
#
# Needs cosign (https://docs.sigstore.dev). For each image it verifies:
#   * the signature, and that the identity behind it is this repository's release workflow running for a v* tag (not a person, not another repository, not a branch);
#   * the SBOM attestation, signed the same way.
# It prints the digest of what it verified. Run the image by that digest (docker-compose.images.yml takes ASTRA_VERSION as a tag; pin the digest where you can): a tag can be moved,
# a digest cannot.
set -eu
TAG="${1:?give the release tag, for example v1.4.0}"
ONLY="${2:-}"
REPO="${ASTRA_REPO:-khidawi/ATRA-Design-Studio}"
OWNER="${REPO%%/*}"
OWNER_LC=$(printf '%s' "$OWNER" | tr 'A-Z' 'a-z')
IDENTITY="^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/v"
ISSUER="https://token.actions.githubusercontent.com"
command -v cosign >/dev/null 2>&1 || { echo "cosign is not installed (https://docs.sigstore.dev/cosign/installation/)."; exit 2; }
VERSION="${TAG#v}"
status=0
for name in backend studio; do
  [ -z "$ONLY" ] || [ "$ONLY" = "$name" ] || continue
  ref="ghcr.io/${OWNER_LC}/astra-${name}:${VERSION}"
  echo "== $ref"
  if out=$(cosign verify "$ref" --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" -o json 2>/dev/null); then
    digest=$(printf '%s' "$out" | sed -n 's/.*"docker-manifest-digest":"\(sha256:[0-9a-f]*\)".*/\1/p' | head -n 1)
    echo "   signature OK, made by the release workflow for a v* tag. digest: ${digest:-unknown}"
  else
    echo "   SIGNATURE NOT VALID: do not run this image."
    status=1
    continue
  fi
  if cosign verify-attestation "$ref" --type spdxjson --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" >/dev/null 2>&1; then
    echo "   SBOM attestation OK"
  else
    echo "   SBOM ATTESTATION NOT VALID"
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "All verified." || echo "Verification failed."
exit "$status"

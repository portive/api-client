import { signJWT } from "@portive/jwt-utils"
import {
  AuthHeaderStruct,
  AuthPayloadStruct,
  AuthPrivateClaims,
  UploadFileResponse,
  UploadProps,
} from "@portive/api-types"
import JWT from "jsonwebtoken"
/**
 * TODO: Change this to use node-fetch by fixing configuration issues with esm
 *
 * https://stackoverflow.com/questions/58211880/uncaught-syntaxerror-cannot-use-import-statement-outside-a-module-when-import
 *
 * We want to use `node-fetch` because this code should not be run in the
 * browser. It requires a `secretKey` and ideally that should not be present
 * in the browser, only on the server.
 */
import fetch from "isomorphic-unfetch"

// eslint-disable-next-line no-secrets/no-secrets
/**
 * Takes an `apiKey` comprising of the parts separates by underscores. The
 * first part being a preamble checking that it starts with `PRTV`, the
 * second is the API key id, and the last pare is the API secret key.
 *
 * The key has these properties for a few reasons:
 *
 * 1. Easy to cut and paste. Double-click and underscores and alphanumeric
 *    are all selected.
 * 2. `PRTV` makes sure we haven't confused the API key with some other API key
 * 3. We encode it into one so that we don't need multiple environment vars
 *    to store the API key which also ensures the key id and secret key stay
 *    together.
 *
 * e.g. PRTV_CfTDX9cq282nQV3K_nJF2aDL4Nf41L3D5Nh8QJtosN0cJvlL0
 */
export function parseApiKey(apiKey: string) {
  const parts = apiKey.split("_")
  if (parts.length !== 3) {
    throw new Error(
      `Expected apiKey to split on _ into exactly 3 parts but is ${parts.length}`
    )
  }
  const [keyType, keyId, secretKey] = parts
  if (keyType !== "PRTV")
    throw new Error(
      `Expected first part of API key to be PRTV but is ${JSON.stringify(
        keyType
      )}`
    )
  return {
    keyType,
    keyId,
    secretKey,
  }
}

// eslint-disable-next-line no-secrets/no-secrets
/**
 * Takes the API key id and the API secret key and merges them into a single
 * API key which includes the `PRTV` preamble.
 *
 * e.g. PRTV_CfTDX9cq282nQV3K_nJF2aDL4Nf41L3D5Nh8QJtosN0cJvlL0
 */
export function stringifyApiKey({
  keyId,
  secretKey,
}: {
  keyId: string
  secretKey: string
}) {
  return `PRTV_${keyId}_${secretKey}`
}

type ExpiresIn = JWT.SignOptions["expiresIn"]

/**
 * A lower level version of `generateAuth` which `generateAuth` uses.
 * Takes the `claims`, `keyId`, `secretKey` and `expiresIn` as separate
 * arguments to make thigns a little more readable.
 *
 * Probably okay to merge this into `generateAuth` later.
 */
export function _generateAuthToken(
  claims: AuthPrivateClaims,
  {
    keyId,
    secretKey,
    expiresIn,
  }: {
    keyId: string // separate from options to prevent accidental inclusion in claims
    secretKey: string // separate from options to prevent accidental inclusion in claims
    expiresIn: ExpiresIn
  }
): string {
  const x = claims
  const jwt = signJWT(claims, AuthPayloadStruct, AuthHeaderStruct, secretKey, {
    keyid: keyId,
    expiresIn,
  })
  return jwt
}

/**
 * Permissions includes both the private claims and the `expiresIn` value
 * for the JWT token. Think of it as the combination of Options for a
 * auth token.
 */
type AuthOptions = AuthPrivateClaims & { expiresIn: ExpiresIn }

/**
 * Takes an apiKey (which includes the `keyId` and `secretKey`) and a set of
 * PermitOptions and then generates a permit from it.
 */
export function generateAuthToken(
  apiKey: string,
  { expiresIn, ...claims }: AuthOptions // PermitPrivateClaims & { expiresIn: ExpiresIn }
) {
  const { keyId, secretKey } = parseApiKey(apiKey)
  return _generateAuthToken(claims, { keyId, secretKey, expiresIn })
}

/**
 * Takes an `authToken` and a set of uploadProps which consists of information
 * about the file and the `recordKey` it will be uploaded to.
 */
export async function fetchUploadPolicy(
  url: string,
  authToken: string,
  uploadProps: Omit<UploadProps, "authToken">
): Promise<UploadFileResponse> {
  const data = { authToken, ...uploadProps }
  const response = await fetch(url, {
    method: "POST",
    mode: "cors",
    cache: "no-cache",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
  return response.json() as unknown as UploadFileResponse
}

/**
 * Allows fetching the uploadPolicy directly on the server using the api key,
 * upload props and a set of authOptions.
 *
 * At the time of writing and testing, we may not recommend this. Giving the
 * authToken to the browser is probably about as fast and gives the necessary
 * options.
 */
export async function fetchUploadPolicyWithApiKey(
  url: string,
  apiKey: string,
  uploadProps: UploadProps,
  permitOptions: AuthOptions
) {
  const permit = generateAuthToken(apiKey, permitOptions)
  return await fetchUploadPolicy(url, permit, uploadProps)
}

import { signJWT } from "@portive/jwt-utils"
import { AuthHeaderStruct, AuthPayloadStruct } from "@portive/api-types"
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

import {
  API_UPLOAD_URL,
  AuthPrivateClaims,
  UploadFileResponse,
  UploadProps,
} from "@portive/api-types"
import JWT from "jsonwebtoken"

export function generateAuth(
  claims: AuthPrivateClaims,
  {
    keyId,
    secretKey,
    expiresIn,
  }: {
    keyId: string // separate from options to prevent accidental inclusion in claims
    secretKey: string // separate from options to prevent accidental inclusion in claims
    expiresIn: JWT.SignOptions["expiresIn"]
  }
): string {
  const x = claims
  const jwt = signJWT(claims, AuthPayloadStruct, AuthHeaderStruct, secretKey, {
    keyid: keyId,
    expiresIn,
  })
  return jwt
}

export async function fetchUploadPolicy(
  auth: string,
  uploadProps: UploadProps
): Promise<UploadFileResponse> {
  const data = { auth, ...uploadProps }
  const response = await fetch(API_UPLOAD_URL, {
    method: "POST",
    mode: "cors",
    cache: "no-cache",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
  return response.json() as unknown as UploadFileResponse
}

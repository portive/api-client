import JWT from "jsonwebtoken"
import {
  parseApiKey,
  stringifyApiKey,
  generateAuthToken,
  _generateAuthToken,
  fetchUploadPolicyWithApiKey,
  fetchUploadPolicy,
} from ".."
import { API_UPLOAD_URL } from "@portive/api-types"

jest.mock("isomorphic-unfetch", () => require("fetch-mock-jest").sandbox())
const fetchMock = require("isomorphic-unfetch")

const KEY_ID = "CfTDX9cq282nQV3K"
const SECRET_KEY = "nJF2aDL4Nf41L3D5Nh8QJtosN0cJvlL0"
const API_KEY = stringifyApiKey({ keyId: KEY_ID, secretKey: SECRET_KEY })

describe("api-client", () => {
  describe("parseApiKey", () => {
    it("should throw if api key is not 3 parts", async () => {
      expect(() => parseApiKey("rueiruewirueiw")).toThrow(
        "exactly 3 parts but is 1"
      )
    })

    it("should throw if first part is not PRTV", async () => {
      expect(() => parseApiKey("AKIA_123_456")).toThrow(
        /expected first part of api key to be PRTV but is "AKIA"/i
      )
    })

    it("should return the parts as expected", async () => {
      const result = parseApiKey("PRTV_alpha_bravo")
      expect(result).toEqual({
        keyType: "PRTV",
        keyId: "alpha",
        secretKey: "bravo",
      })
    })
  })

  describe("stringifyApiKey", () => {
    it("should create an apiKey from the parts of an apiKey", async () => {
      const apiKey = stringifyApiKey({ keyId: "keyid", secretKey: "secretkey" })
      expect(apiKey).toEqual("PRTV_keyid_secretkey")
    })
  })

  describe("_generatePermit", () => {
    it("generate and decode a simple permit", async () => {
      const permit = _generateAuthToken(
        { path: "**/*" },
        {
          keyId: KEY_ID,
          secretKey: SECRET_KEY,
          expiresIn: "1h",
        }
      )
      const complete = JWT.verify(permit, SECRET_KEY, { complete: true })
      expect(complete).toEqual({
        header: { alg: "HS256", typ: "JWT", kid: "CfTDX9cq282nQV3K" },
        payload: {
          path: "**/*",
          iat: expect.any(Number),
          exp: expect.any(Number),
        },
        signature: expect.stringMatching(/^[a-zA-z0-9-_]+$/),
      })
    })

    it("should fail to generate an invalid permit in the options", async () => {
      expect(() =>
        _generateAuthToken(
          { path: "**/*" },
          {
            keyId: 123 as any, // force an error
            secretKey: SECRET_KEY,
            expiresIn: "1h",
          }
        )
      ).toThrow(`"keyid" must be a string`)
    })

    it("should fail to generate an invalid permit in the claims", async () => {
      expect(() =>
        _generateAuthToken(
          { path: 123 as any }, // force an error
          {
            keyId: KEY_ID,
            secretKey: SECRET_KEY,
            expiresIn: "1h",
          }
        )
      ).toThrow(`Error validating JWT Payload. At path: path`)
    })

    it("should fail if secretKey is missing", async () => {
      expect(
        () =>
          _generateAuthToken({ path: "**/*" }, {
            keyId: KEY_ID,
            expiresIn: "1h",
          } as any) // force an error (missing `secretKey`)
      ).toThrow(`secretOrPrivateKey must have a value`)
    })
  })

  describe("generatePermit", () => {
    it("should generate permissions", async () => {
      const permit = generateAuthToken(API_KEY, {
        path: "**/*",
        expiresIn: "1d",
      })
      const complete = JWT.verify(permit, SECRET_KEY, { complete: true })
      expect(complete).toEqual({
        header: { alg: "HS256", typ: "JWT", kid: "CfTDX9cq282nQV3K" },
        payload: {
          path: "**/*",
          iat: expect.any(Number),
          exp: expect.any(Number),
        },
        signature: expect.any(String),
      })
    })
  })

  describe("fetchUploadPolicy", () => {
    afterEach(() => {
      fetchMock.restore()
    })
    it("should fetch an upload", async () => {
      fetchMock.mock("https://api.portive.com/api/v1/upload", {
        status: 200,
        body: {},
      })
      const authToken = _generateAuthToken(
        { path: "**/*" },
        {
          keyId: KEY_ID,
          secretKey: SECRET_KEY,
          expiresIn: 60 * 60,
        }
      )
      await fetchUploadPolicy(API_UPLOAD_URL, authToken, {
        path: "articles/123",
        file: {
          type: "generic",
          filename: "1kbfile.txt",
          contentType: "text/plain",
          bytes: 1024,
        },
      })
      const [url, request] = fetchMock.lastCall()
      expect(url).toEqual("https://api.portive.com/api/v1/upload")
      expect(request).toEqual({
        method: "POST",
        mode: "cors",
        cache: "no-cache",
        headers: { "Content-Type": "application/json" },
        body: expect.any(String), //'{"permit":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkNmVERYOWNxMjgyblFWM0sifQ.eyJhY2NlcHREb2N1bWVudEtleXMiOiIqKi8qIiwiaWF0IjoxNjUxNTI1NzE5LCJleHAiOjE2NTE1MjkzMTl9.HVFNOnGQI7JETTqkQ_zRUK41hIJD78R8USTwFzyAvfI","documentKey":"articles/123","file":{"type":"generic","bytes":1024}}',
      })
      const json = JSON.parse(request.body)
      expect(json).toEqual({
        authToken: expect.any(String),
        path: "articles/123",
        file: {
          type: "generic",
          filename: "1kbfile.txt",
          contentType: "text/plain",
          bytes: 1024,
        },
      })
    })
  })
})

import JWT from "jsonwebtoken"
import { fetchUploadPolicy, generateAuth } from ".."

jest.mock("isomorphic-unfetch", () => require("fetch-mock-jest").sandbox())
const fetchMock = require("isomorphic-unfetch")

const KEY_ID = "CfTDX9cq282nQV3K"
const SECRET_KEY = "nJF2aDL4Nf41L3D5Nh8QJtosN0cJvlL0"

describe("api-client", () => {
  describe("generateAuth", () => {
    it("generate and decode a simple auth", async () => {
      const auth = generateAuth(
        { acceptDocumentKeys: "**/*" },
        {
          keyId: KEY_ID,
          secretKey: SECRET_KEY,
          expiresIn: "1h",
        }
      )
      const complete = JWT.verify(auth, SECRET_KEY, { complete: true })
      expect(complete).toEqual({
        header: { alg: "HS256", typ: "JWT", kid: "CfTDX9cq282nQV3K" },
        payload: {
          acceptDocumentKeys: "**/*",
          iat: expect.any(Number),
          exp: expect.any(Number),
        },
        signature: expect.stringMatching(/^[a-zA-z0-9-_]+$/),
      })
    })

    it("should fail to generate an invalid auth in the options", async () => {
      expect(() =>
        generateAuth(
          { acceptDocumentKeys: "**/*" },
          {
            keyId: 123 as any, // force an error
            secretKey: SECRET_KEY,
            expiresIn: "1h",
          }
        )
      ).toThrow(`"keyid" must be a string`)
    })

    it("should fail to generate an invalid auth in the claims", async () => {
      expect(() =>
        generateAuth(
          { acceptDocumentKeys: 123 as any }, // force an error
          {
            keyId: KEY_ID,
            secretKey: SECRET_KEY,
            expiresIn: "1h",
          }
        )
      ).toThrow(`Error validating JWT Payload. At path: acceptDocumentKeys`)
    })

    it("should fail if secretKey is missing", async () => {
      expect(
        () =>
          generateAuth({ acceptDocumentKeys: "**/*" }, {
            keyId: KEY_ID,
            expiresIn: "1h",
          } as any) // force an error (missing `secretKey`)
      ).toThrow(`secretOrPrivateKey must have a value`)
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
      const auth = generateAuth(
        { acceptDocumentKeys: "**/*" },
        {
          keyId: KEY_ID,
          secretKey: SECRET_KEY,
          expiresIn: 60 * 60,
        }
      )
      const uploadPolicy = await fetchUploadPolicy(auth, {
        documentKey: "articles/123",
        file: {
          type: "generic",
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
        body: expect.any(String), //'{"auth":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkNmVERYOWNxMjgyblFWM0sifQ.eyJhY2NlcHREb2N1bWVudEtleXMiOiIqKi8qIiwiaWF0IjoxNjUxNTI1NzE5LCJleHAiOjE2NTE1MjkzMTl9.HVFNOnGQI7JETTqkQ_zRUK41hIJD78R8USTwFzyAvfI","documentKey":"articles/123","file":{"type":"generic","bytes":1024}}',
      })
      const json = JSON.parse(request.body)
      expect(json).toEqual({
        auth: expect.any(String),
        documentKey: "articles/123",
        file: { type: "generic", bytes: 1024 },
      })
    })
  })
})

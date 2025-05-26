# JWT Auth (Node.js)

> A JWT authentication package providing both Access Token and Refresh Token mechanisms, featuring fingerprint recognition, Redis storage, and automatic refresh functionality.<br>
> version Golang can get [here](https://github.com/pardnchiu/golang-jwt-auth)

[![version](https://img.shields.io/npm/v/@pardnchiu/jwt-auth)](https://www.npmjs.com/package/@pardnchiu/jwt-auth)

## Feature

- ### Dual Token System
  - Access Token (short-term) + Refresh Token (long-term)
  - Automatic token refresh without requiring re-login
  - ES256 algorithm (Elliptic Curve Digital Signature)
- ### Device Fingerprinting
  - Generates unique fingerprints based on User-Agent, Device ID, OS, and Browser
  - Prevents token misuse across different devices
  - Automatic device type detection (Desktop, Mobile, Tablet)
- ### Token Revocation
  - Adds Access Token to blacklist upon logout
  - Redis TTL automatically cleans expired revocation records
  - Prevents reuse of logged-out tokens
- ### Version Control Protection
  - Refresh Token version tracking
  - Auto-generates new Refresh ID after 5 refresh attempts
  - Prevents replay attacks
- ### Smart Refresh Strategy
  - Auto-regenerates when Refresh Token has less than half lifetime remaining
  - 5-second grace period for old tokens to reduce concurrency issues
  - Minimizes database queries
- ### Multiple Authentication Methods
  - Automatic cookie reading
  - Authorization Bearer Header
  - Custom Headers (X-Device-ID, X-Refresh-ID)
- ### Flexible Configuration
  - Supports file paths or direct key content
  - Customizable Cookie names
  - Production/Development environment auto-switching

## How to use

- ### Installation
  ```bash
  npm install @pardnchiu/jwt-auth
  ```
- ### Initialize
  ```typescript
  import { JWTAuth } from '@pardnchiu/jwt-auth';

  // initialize the JWT instance
  await JWTAuth.init({
    privateKeyPath: "./keys/private.pem",
    publicKeyPath: "./keys/public.pem",
    // or paste keys directly:
    // privateKey: "-----BEGIN EC PRIVATE KEY-----...",
    // publicKey: "-----BEGIN PUBLIC KEY-----...",
    accessTokenExpires: 900, // seconds
    refreshTokenExpires: 604800, // seconds
    // true: domain=domain, samesite=none, secure=true
    // false: domain=localhost, samesite=lax, secure=false
    isProd: false,
    domain: "pardn.io",
    // cookie key, default access_token/refresh_id
    AccessTokenCookieKey: "access_token",
    RefreshTokenCookieKey: "refresh_id",
    // store with redis
    redis: {
      host: "localhost",
      port: 6379,
      password: "", // optional
      db: 0 // optional
    },
    checkUserExists: async (userId: string): Promise<boolean> => {
      // return true if user exists, false otherwise
      return true;
    }
  });

  process.on("SIGINT", async () => {
    await JWTAuth.close();
    process.exit(0);
  });
  ```
- ### CreateJWT
  ```typescript
  import { Request, Response } from 'express';
  import { JWTAuth } from '@pardnchiu/jwt-auth';

  async function loginHandler(req: Request, res: Response) {
    // after verifying user login info...
    
    const userData = {
      id: "user123",
      name: "",
      email: "john@example.com",
      thumbnail: "avatar.jpg",
      role: "user",
      level: 1,
      scope: ["read", "write"]
    };

    try {
      const tokenResult = await JWTAuth.CreateJWT(req, res, userData);
      
      // automatically set in cookies
      res.json({
        success: true,
        token: tokenResult.token,
        refresh_id: tokenResult.refresh_id
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
  ```
- ### VerifyJWT
  ```typescript
  import { Request, Response } from 'express';
  import { JWTAuth } from '@pardnchiu/jwt-auth';

  async function protectedHandler(req: Request, res: Response) {
    try {
      const result = await JWTAuth.VerifyJWT(req, res);
      
      if (typeof result === "number") {
        // Authentication failed, result is HTTP status code (401/400)
        return res.status(result).json({ 
          error: result === 401 ? "Unauthorized" : "Bad Request" 
        });
      }
      
      // Authentication success, result is user data
      res.json({
        message: "Protected resource accessed",
        user: result
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
  ```
- ### RevokeJWT
  ```typescript
  import { Request, Response } from "express";
  import { JWTAuth } from "@pardnchiu/jwt-auth";

  async function logoutHandler(req: Request, res: Response) {
    try {
      await JWTAuth.RevokeJWT(req, res);
      
      res.json({
        message: "Successfully logged out"
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
  ```

## Configuration

### Config
- `privateKeyPath` / `privateKey`: private key file path or content
- `publicKeyPath` / `publicKey`: public key file path or content  
- `accessTokenExpires`: access token expire time
- `refreshTokenExpires`: refresh id expire time
- `isProd`: is production or not (affects cookie setting)
- `domain`: cookie domain
- `redis`: redis connection
  - `host`: redis host
  - `port`: redis port
  - `password`: redis password (optional)
  - `db`: redis db (optional)
- `checkUserExists`: user existence check function
- `AccessTokenCookieKey`: access token cookie name (default: 'access_token')
- `RefreshTokenCookieKey`: refresh id cookie name (default: 'refresh_id')

### Supported methods

1. **Cookie**: Automatically reads token from cookie
2. **Authorization Header**: `Authorization: Bearer <token>`
3. **Custom Headers**: 
   - `X-Device-ID`: Device ID
   - `X-Refresh-ID`: Custom Refresh ID

## Token refresh

The system automatically generates a new Refresh ID in the following cases:
- Refresh version exceeds 5 times
- Remaining Refresh Token time is less than half

The new tokens are returned via:
- HTTP Header: `X-New-Access-Token`
- HTTP Header: `X-New-Refresh-ID`
- Cookie auto-update

## Security features

- **Fingerprint recognition**: Generates a unique fingerprint based on User-Agent, Device-ID, OS, Browser, and Device type
- **Token revocation**: Adds token to a blacklist on logout
- **Automatic expiration**: Supports TTL to automatically clean up expired tokens
- **Version control**: Tracks Refresh Token versions to prevent replay attacks
- **Fingerprint validation**: Ensures tokens are used from the same device/browser

## Error handling

The `VerifyJWT` method returns:
- `AuthData` object on successful authentication
- HTTP status code number on failure:
  - `401`: Unauthorized (invalid/expired tokens, user doesn't exist)
  - `400`: Bad Request (invalid fingerprint, malformed tokens)

Common error scenarios:
- Token revoked
- Fingerprint mismatch
- Refresh data not found
- JWT expired or invalid
- User not found

## License

This source code project is licensed under the [MIT](https://github.com/pardnchiu/nodejs-jwt-auth/blob/main/LICENSE) license.

## Creator

<img src="https://avatars.githubusercontent.com/u/25631760" align="left" width="96" height="96" style="margin-right: 0.5rem;">

<h4 style="padding-top: 0">邱敬幃 Pardn Chiu</h4>

<a href="mailto:dev@pardn.io" target="_blank">
    <img src="https://pardn.io/image/email.svg" width="48" height="48">
</a> <a href="https://linkedin.com/in/pardnchiu" target="_blank">
    <img src="https://pardn.io/image/linkedin.svg" width="48" height="48">
</a>

***

©️ 2025 [邱敬幃 Pardn Chiu](https://pardn.io)
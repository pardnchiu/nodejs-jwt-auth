import { Request, Response } from "express";
import { Session } from "express-session";
import { readFileSync } from "fs";
import { decode, sign, verify } from "jsonwebtoken";
import { createClient, RedisClientType } from "redis";
import CreateFingerprint from "./CreateFingerprint";
import CreateRefreshId from "./CreateRefreshId";
import { AuthData, Config, JWTPayload, RefreshData, TokenResult, VerifyResult } from "./type";

export class JWTAuth {
  private static config: Config | null = null;
  private static redisClient: RedisClientType | null = null;

  private constructor() { }

  public static async init(config: Config): Promise<void> {
    this.config = config;

    if (!config.publicKey && !config.publicKeyPath) {
      throw new Error("publicKey is required");
    }
    else if (typeof config.publicKeyPath === "string") {
      this.config.publicKey = readFileSync(config.publicKeyPath, "utf8");
    }

    if (!config.privateKey && !config.privateKeyPath) {
      throw new Error("privateKey is required");
    }
    else if (typeof config.privateKeyPath === "string") {
      this.config.privateKey = readFileSync(config.privateKeyPath, "utf8");
    }

    this.config.AccessTokenCookieKey = config.AccessTokenCookieKey || "access_token";
    this.config.RefreshTokenCookieKey = config.RefreshTokenCookieKey || "refresh_id";

    this.redisClient = createClient({
      socket: {
        host: config.redis.host || "localhost",
        port: config.redis.port || 6379,
      },
      password: config.redis.password || undefined,
      database: config.redis.db || 0
    });

    try {
      await this.redisClient.connect();
    }
    catch (err) {
      console.error("JWTAuth failed:", err);
      throw err;
    }
  }

  public static async close(): Promise<void> {
    try {
      if (this.redisClient) {
        await this.redisClient.disconnect();
        this.redisClient = null;
      }
    }
    catch (err) {
      console.error("JWTAuth failed:", err);
      throw err;
    }
  }

  private static async getRefreshData(req: Request, refresh_id?: string): Promise<RefreshData | undefined> {
    if (!this.redisClient || !this.config) {
      throw new Error("JWTAuth not init");
    }

    const fp = (req as any).session?.fp || await CreateFingerprint(req);
    refresh_id = refresh_id || this.getRefreshId(req);

    return new Promise(async (resolve, reject) => {
      if (!refresh_id) {
        return resolve(undefined);
      }

      try {
        const result = await this.redisClient!.get("refresh:" + refresh_id);

        if (!result) {
          throw new Error("refresh data 不存在");
        }

        const json = JSON.parse(result) as RefreshData;

        if (json.fp !== fp) {
          throw new Error("指紋不匹配");
        }

        resolve(json);
      } catch (err) {
        reject(err);
      }
    });
  }

  private static async updateRefreshData(req: Request, refresh_id?: string): Promise<string | undefined> {
    if (!this.redisClient || !this.config) {
      throw new Error("JWTAuth not init");
    }

    const fp = (req as any).session?.fp || await CreateFingerprint(req);
    const dateNow = new Date();
    const refreshKey = this.getRefreshId(req);

    if (!refresh_id && !refreshKey) {
      return;
    }

    refresh_id = refresh_id || refreshKey!;

    try {
      const result = await this.redisClient.get("refresh:" + refresh_id);

      if (!result) {
        throw new Error("refresh data 不存在");
      }

      let refreshData = JSON.parse(result) as RefreshData;

      if (refreshData.fp !== fp) {
        throw new Error("指紋不匹配");
      }

      refreshData.expires_at = new Date(dateNow.getTime() + (this.config.refreshTokenExpires * 1000));
      refreshData.version += 1;

      const ttl = await this.redisClient.ttl("refresh:" + refresh_id);

      if (refreshData.version > 5 || ttl < (this.config.refreshTokenExpires / 2)) {
        // 舊的 refresh token 5 秒內有效（減少併發請求錯誤）
        await this.redisClient.setEx("refresh:" + refresh_id, 5, JSON.stringify(refreshData));

        // 重新生成 refresh_id
        refresh_id = await CreateRefreshId(refreshData.data, fp);

        refreshData.version = 0;
      }

      await this.redisClient.setEx("refresh:" + refresh_id, this.config.refreshTokenExpires, JSON.stringify(refreshData));

      return refresh_id;
    } catch (err) {
      throw err;
    }
  }

  private static getAccessToken(req: Request & { session: Session }): string | null {
    if (!this.config) {
      throw new Error("JWTAuth not init");
    }

    req.session = req.session || {};

    if (req.headers && req.headers.authorization) {
      const match = req.headers.authorization.match(/^Bearer\s+(.*)$/);

      if (match && match[1]) {
        return match[1];
      }
    }

    if (req.cookies && req.cookies[this.config.AccessTokenCookieKey]) {
      return req.cookies[this.config.AccessTokenCookieKey];
    }

    return null;
  }

  private static getRefreshId(req: Request): string | undefined {
    if (!this.config) {
      throw new Error("JWTAuth not init");
    }

    if (req.headers) {
      const headerRefreshId = req.headers["X-Refresh-ID"] || req.headers["x-refresh-id"];

      if (headerRefreshId) {
        return headerRefreshId as string;
      }
    }

    if (req.cookies && req.cookies[this.config.RefreshTokenCookieKey]) {
      return req.cookies[this.config.RefreshTokenCookieKey];
    }

    return;
  }

  public static async VerifyJWT(req: Request, res: Response): Promise<VerifyResult> {
    if (this.redisClient == null || this.config == null || this.config.publicKey == null || this.config.privateKey == null) {
      throw new Error("JWTAuth not initialized. Call JWTAuth.init() first.");
    };

    const fp = (req as any).session?.fp || await CreateFingerprint(req);
    const accessToken = this.getAccessToken(req);
    let refresh_id = this.getRefreshId(req);
    const dateNow = new Date();

    if (await this.redisClient.get("revoke:" + accessToken)) {
      return {
        isAuth: false,
        isError: false,
        isGuest: true
      };
    }

    try {
      let isExpired = false;
      let authData: AuthData = {} as AuthData;
      let refreshData: RefreshData = {} as RefreshData;

      if (accessToken == null && refresh_id == null) {
        return {
          isAuth: false,
          isError: false,
          isGuest: true
        };
      }
      else if (accessToken == null && refresh_id != null) {
        isExpired = true;

        try {
          refreshData = await this.getRefreshData(req) || {} as RefreshData;
        } catch (err: any) {
          console.error(err.message);
          return {
            isAuth: false,
            isError: err.message === "refresh data 不存在",
            isGuest: true
          };
        }
      }
      else if (accessToken != null) {
        try {
          const verifyJWT = verify(accessToken, this.config.publicKey) as JWTPayload

          if (verifyJWT.fp !== fp) {
            return {
              isAuth: false,
              isError: true,
              isGuest: true
            };
          }

          authData = {
            id: verifyJWT.id,
            name: verifyJWT.name,
            email: verifyJWT.email,
            thumbnail: verifyJWT.thumbnail,
            level: verifyJWT.level,
            role: verifyJWT.role,
            scope: verifyJWT.scope
          };
        } catch (err: any) {
          if (err.message !== "jwt expired") {
            return {
              isAuth: false,
              isError: true,
              isGuest: true
            };
          }

          isExpired = true;

          try {
            const decodeJWT = decode(accessToken) as {
              fp: string;
              refresh_id: string;
            };

            if (decodeJWT.fp !== fp) {
              return {
                isAuth: false,
                isError: true,
                isGuest: true
              };
            }

            refresh_id = decodeJWT.refresh_id;
            refreshData = await this.getRefreshData(req, decodeJWT.refresh_id) || {} as RefreshData;
          } catch (err: any) {
            console.error(err.message);
            return {
              isAuth: false,
              isError: err.message === "refresh data 不存在",
              isGuest: true
            };
          }
        }
      }

      if (!isExpired) {
        return {
          data: authData,
          isAuth: true,
          isError: false,
          isGuest: false
        };
      }

      if (!refreshData.data.id) {
        return {
          isAuth: false,
          isError: false,
          isGuest: true
        };
      }

      try {
        if (refresh_id) {
          refresh_id = await this.updateRefreshData(req, refresh_id);
        }

        // 獲取用戶資訊
        const result = await this.config.checkUserExists(refreshData.data.id);

        if (!result) {
          return {
            isAuth: false,
            isError: false,
            isGuest: true
          };
        }

        authData = refreshData.data;

        const newAccessToken = sign(
          {
            ...authData,
            fp: fp,
            version: refreshData.version,
            refresh_id: refresh_id
          },
          this.config.privateKey,
          {
            algorithm: "ES256",
            expiresIn: this.config.accessTokenExpires
          }
        );

        res.setHeader("X-New-Access-Token", newAccessToken);
        res.setHeader("X-New-Refresh-ID", refresh_id!);

        res.cookie(this.config.AccessTokenCookieKey, newAccessToken, {
          httpOnly: true,
          secure: this.config.isProd,
          sameSite: this.config.isProd ? "none" : "lax",
          expires: new Date(dateNow.getTime() + this.config.accessTokenExpires * 1000),
          maxAge: this.config.accessTokenExpires * 1000,
          path: "/",
          domain: this.config.isProd ? this.config.domain : "localhost"
        });

        res.cookie(this.config.RefreshTokenCookieKey, refresh_id, {
          httpOnly: true,
          secure: this.config.isProd,
          sameSite: this.config.isProd ? "none" : "lax",
          expires: new Date(dateNow.getTime() + this.config.refreshTokenExpires * 1000),
          maxAge: this.config.refreshTokenExpires * 1000,
          path: "/",
          domain: this.config.isProd ? this.config.domain : "localhost"
        });

        return {
          data: authData,
          isAuth: true,
          isError: false,
          isGuest: false
        };
      } catch (err: any) {
        console.error(err.message);
        return {
          isAuth: false,
          isError: err.message === "refresh data 不存在",
          isGuest: true
        };
      }
    } catch (err: any) {
      console.error(err.message);
      return {
        isAuth: false,
        isError: true,
        isGuest: true
      };
    }
  }

  public static async CreateJWT(req: Request, res: Response, user: AuthData): Promise<TokenResult> {
    if (this.redisClient == null || this.config == null || this.config.publicKey == null || this.config.privateKey == null) {
      throw new Error("JWTAuth not initialized. Call JWTAuth.init() first.");
    };

    const fp = (req as any).session?.fp || await CreateFingerprint(req);
    const dateNow = new Date();

    const refresh_id = await CreateRefreshId(user, fp);

    // 生成 access token
    const token = sign(
      {
        id: user.id,
        name: user.name,
        email: user.email,
        thumbnail: user.thumbnail,
        level: user.level,
        role: user.role,
        scope: user.scope || [],
        fp: fp,
        refresh_id: refresh_id
      },
      this.config.privateKey,
      {
        algorithm: "ES256",
        expiresIn: this.config.accessTokenExpires
      }
    );

    res.cookie(this.config.AccessTokenCookieKey, token, {
      httpOnly: true,
      secure: this.config.isProd,
      sameSite: this.config.isProd ? "none" : "lax",
      expires: new Date(dateNow.getTime() + this.config.accessTokenExpires * 1000),
      maxAge: this.config.accessTokenExpires * 1000,
      path: "/",
      domain: this.config.isProd ? this.config.domain : "localhost"
    });

    // 生成 refresh_token
    await this.redisClient.setEx(
      "refresh:" + refresh_id,
      this.config.refreshTokenExpires,
      JSON.stringify({
        data: user,
        version: 1,
        fp: fp,
        expires_at: new Date(dateNow.getTime() + this.config.refreshTokenExpires * 1000),
        issued_at: dateNow,
      })
    );

    res.cookie(this.config.RefreshTokenCookieKey, refresh_id, {
      httpOnly: true,
      secure: this.config.isProd,
      sameSite: this.config.isProd ? "none" : "lax",
      expires: new Date(dateNow.getTime() + this.config.refreshTokenExpires * 1000),
      maxAge: this.config.refreshTokenExpires * 1000,
      path: "/",
      domain: this.config.isProd ? this.config.domain : "localhost"
    });

    return {
      token: token,
      refresh_id: refresh_id,
    };
  }

  public static async RevokeJWT(req: Request, res: Response, refresh_id?: string): Promise<void> {
    if (this.redisClient == null || this.config == null || this.config.publicKey == null || this.config.privateKey == null) {
      throw new Error("JWTAuth not initialized. Call JWTAuth.init() first.");
    };

    const refreshId = this.getRefreshId(req);
    const accessToken = this.getAccessToken(req);

    if (!refresh_id && !refreshId) {
      return;
    }

    refresh_id = refresh_id || refreshId!;

    try {
      await res.clearCookie(this.config.AccessTokenCookieKey, {
        httpOnly: true,
        secure: this.config.isProd,
        sameSite: this.config.isProd ? "none" : "lax",
        path: "/",
        domain: this.config.isProd ? this.config.domain : "localhost"
      });

      await res.clearCookie(this.config.RefreshTokenCookieKey, {
        httpOnly: true,
        secure: this.config.isProd,
        sameSite: this.config.isProd ? "none" : "lax",
        path: "/",
        domain: this.config.isProd ? this.config.domain : "localhost"
      });

      const result = await this.redisClient.get("refresh:" + refresh_id);

      if (!result) {
        throw new Error("refresh data 不存在");
      }

      const refreshData = JSON.parse(result) as RefreshData;
      // 舊的 refresh token 5 秒內有效（減少併發請求錯誤）
      await this.redisClient.setEx("refresh:" + refresh_id, 5, JSON.stringify(refreshData));
      await this.redisClient.setEx("revoke:" + accessToken, this.config.accessTokenExpires, "1");
    } catch (err: any) {
      if (err.message !== "refresh data 不存在") {
        console.error(err);
      }
    }
  }

  public static GetAuth(auth: AuthData | number) {
    return {
      ...(typeof auth === "number" ? {} : auth),
      isAuth: auth != 400 && auth != 401,
      isError: auth == 400,
      isGuest: auth == 401 || auth == 400
    };
  }
}

// 監聽程序結束信號，自動關閉連接
process.on("SIGINT", async _ => {
  await JWTAuth.close();
  process.exit(0);
});

process.on("SIGTERM", async _ => {
  await JWTAuth.close();
  process.exit(0);
});

export default JWTAuth;
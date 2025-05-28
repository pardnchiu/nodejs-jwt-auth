export interface Config {
  publicKeyPath?: string;
  privateKeyPath?: string;
  publicKey?: string;
  privateKey?: string;
  accessTokenExpires: number;
  refreshTokenExpires: number;
  isProd: boolean;
  domain?: string;
  redis: {
    host: string;
    port: number;
    password?: string;
    db?: number;
  };
  checkUserExists: (userId: string) => Promise<boolean>;
  AccessTokenCookieKey: string;
  RefreshTokenCookieKey: string;
}

export interface VerifyResult {
  data?: AuthData;
  isAuth: boolean;
  isError: boolean;
  isGuest: boolean;
}

export interface AuthData {
  id: string;
  name: string;
  email: string;
  thumbnail?: string;
  level?: number;
  role?: string;
  scope?: string[];
}

export interface RefreshData {
  data: AuthData,
  version: number;
  fp: string;
  expires_at: Date;
  issued_at: Date;
}

export interface JWTPayload {
  id: string;
  name: string;
  email: string;
  thumbnail?: string;
  level?: number;
  role?: string;
  scope?: string[];
  fp: string;
  refresh_id: string;
}

export interface TokenResult {
  token: string;
  refresh_id: string;
}

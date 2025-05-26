import crypto from "crypto";
import { AuthData } from "./type";

export default async function createRefreshId(user: AuthData, fp: string): Promise<string> {
  const data = {
    ...user,
    fp: fp,
    issued_at: new Date()
  };

  return crypto
    .createHash("sha256")
    .update(JSON.stringify(data))
    .digest("hex");
}
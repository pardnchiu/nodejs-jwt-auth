import crypto from "crypto";
import { Request } from "express";

export default async function CreateFingerprint(req: Request): Promise<string> {
  const userAgent = req.headers["user-agent"] || "Unknown";

  function getOS(): string {
    switch (true) {
      case (/Windows/.test(userAgent)): return "Windows";
      case (/Macintosh|Mac OS X/.test(userAgent)): return "MacOS";
      case (/Linux/.test(userAgent)): return "Linux";
      case (/Android/.test(userAgent)): return "Android";
      case (/iPhone|iPad|iPod/.test(userAgent)): return "iOS";
      default: return "Unknown_OS";
    }
  }

  function getBrowser(): string {
    switch (true) {
      case (/Edge|Edg/.test(userAgent)): return "Edge";
      case (/Firefox/.test(userAgent)): return "Firefox";
      case (/Chrome/.test(userAgent)): return "Chrome";
      case (/Safari/.test(userAgent)): return "Safari";
      case (/Opera|OPR/.test(userAgent)): return "Opera";
      default: return "Unknown_Browser";
    }
  }

  function getDevice(): string {
    switch (true) {
      case (/iPad/.test(userAgent)): return "Tablet";
      case (/iPhone|iPod|Android.*Mobile|BlackBerry|IEMobile|Opera Mini/.test(userAgent)): return "Mobile";
      default: return "Desktop";
    }
  }

  const fingerprintData = {
    os: getOS(),
    browser: getBrowser(),
    device: getDevice(),
    deviceId: req.headers["X-Device-ID"] || req.headers["x-device-id"] || (req as any).body?.deviceId || "Unknown",
  };

  const fp = JSON.stringify(fingerprintData);

  return crypto
    .createHash("sha256")
    .update(fp)
    .digest("hex");
}
import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { env } from "../../config/env";
import { JWT_AUDIENCE, JWT_ISSUER } from "./auth.constants";
import { AuthError } from "./auth.error";
import { Role, isRole } from "./auth.model";

interface AccessTokenPayload extends JwtPayload {
  role?: unknown;
}

const readBearerToken = (req: Request): string | undefined => {
  const authorization = req.header("authorization");
  return authorization?.startsWith("Bearer ")
    ? authorization.slice(7).trim()
    : undefined;
};

const authenticate = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const token = readBearerToken(req);
  if (!token) {
    res.status(401).json({ message: "Authentication required" });
    return;
  }

  try {
    const payload = jwt.verify(token, env.JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as AccessTokenPayload | string;
    if (
      typeof payload === "string" ||
      typeof payload.sub !== "string" ||
      !isRole(payload.role)
    ) {
      throw new AuthError("Invalid access token", 401);
    }

    req.auth = {
      userId: payload.sub,
      role: payload.role,
    };
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired access token" });
  }
};

const authorize =
  (...allowedRoles: Role[]) =>
  (req: Request, res: Response, next: NextFunction): void => {
    if (!req.auth) {
      res.status(401).json({ message: "Authentication required" });
      return;
    }
    if (!allowedRoles.includes(req.auth.role)) {
      res.status(403).json({ message: "Insufficient permissions" });
      return;
    }
    next();
  };

const requireAuth = (req: Request): { userId: string; role: Role } => {
  if (!req.auth) {
    throw new AuthError("Authentication required", 401);
  }
  return req.auth;
};

export { authenticate, authorize, requireAuth };

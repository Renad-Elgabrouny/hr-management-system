import dotenv from "dotenv";
import { existsSync } from "fs";
import { resolve } from "path";

const defaultEnvPath = existsSync(resolve(process.cwd(), ".env"))
  ? resolve(process.cwd(), ".env")
  : resolve(process.cwd(), "src", ".env");
dotenv.config({ path: process.env.ENV_FILE || defaultEnvPath });

export interface EnvConfig {
  PORT: number;
  MONGO_URI: string;
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
}

const jwtSecret = process.env.JWT_SECRET || "";
const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI || "";
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || "1d";
const port = Number.parseInt(process.env.PORT || "3000", 10);

if (jwtSecret.length < 32) {
  throw new Error("JWT_SECRET must be configured with at least 32 characters");
}
if (!mongoUri) {
  throw new Error("MONGO_URI or MONGODB_URI must be configured");
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535");
}
if (!/^\d+[smhd]$/.test(jwtExpiresIn)) {
  throw new Error(
    'JWT_EXPIRES_IN must be a duration such as "15m", "8h", or "1d"',
  );
}

export const env: EnvConfig = {
  PORT: port,
  MONGO_URI: mongoUri,
  JWT_SECRET: jwtSecret,
  JWT_EXPIRES_IN: jwtExpiresIn,
};

export default env;

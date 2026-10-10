import type { Role } from "../modules/auth/auth.model";

declare global {
  namespace Express {
    interface Request {
      auth?: {
        userId: string;
        role: Role;
      };
    }
  }
}

export {};

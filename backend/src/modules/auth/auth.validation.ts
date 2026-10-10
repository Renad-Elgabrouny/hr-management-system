import { RequestHandler } from "express";
import { AuthError } from "./auth.error";
import { OTPChannel } from "./otp/otp.model";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const requireBody =
  (validate: (body: Record<string, unknown>) => void): RequestHandler =>
  (req, res, next) => {
    try {
      if (!isRecord(req.body)) {
        throw new AuthError("A JSON request body is required", 400);
      }
      validate(req.body);
      next();
    } catch (error) {
      if (error instanceof AuthError) {
        res.status(error.statusCode).json({ message: error.message });
        return;
      }
      next(error);
    }
  };

const requireString = (
  body: Record<string, unknown>,
  field: string,
  minLength = 1,
  maxLength = 320,
): string => {
  const value = body[field];
  if (
    typeof value !== "string" ||
    value.trim().length < minLength ||
    value.length > maxLength
  ) {
    throw new AuthError(`${field} is invalid`, 400);
  }
  return value.trim();
};

const validateEmail = (value: string): void => {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || value.length > 254) {
    throw new AuthError("A valid email address is required", 400);
  }
};

const requireNewPassword = (
  body: Record<string, unknown>,
  field: string,
): string => {
  const value = body[field];
  if (
    typeof value !== "string" ||
    value.length < 12 ||
    Buffer.byteLength(value, "utf8") > 72
  ) {
    throw new AuthError(`${field} must be 12-72 UTF-8 bytes`, 400);
  }
  return value;
};

const requireOtp = (body: Record<string, unknown>): void => {
  if (!/^\d{6}$/.test(requireString(body, "otp", 6, 6))) {
    throw new AuthError("OTP must contain six digits", 400);
  }
};

const validateRegister = requireBody((body) => {
  const email = requireString(body, "email");
  requireNewPassword(body, "password");
  validateEmail(email);

  const channel = body.channel ?? OTPChannel.EMAIL;
  if (!Object.values(OTPChannel).includes(channel as OTPChannel)) {
    throw new AuthError("Unsupported verification channel", 400);
  }
  body.channel = channel;

  if (channel === OTPChannel.SMS) {
    const phone = requireString(body, "phoneNumber", 8, 16);
    if (!/^\+[1-9]\d{7,14}$/.test(phone)) {
      throw new AuthError("phoneNumber must use E.164 format", 400);
    }
  }
});

const validateLogin = requireBody((body) => {
  const email = requireString(body, "email");
  const password = body.password;
  if (
    typeof password !== "string" ||
    !password ||
    Buffer.byteLength(password, "utf8") > 72
  ) {
    throw new AuthError("password is invalid", 400);
  }
  validateEmail(email);
});

const validateUserOtp = requireBody((body) => {
  const email = requireString(body, "email");
  validateEmail(email);
  requireOtp(body);
});

const validateResendOtp = requireBody((body) => {
  const email = requireString(body, "email");
  validateEmail(email);
  if (
    body.channel !== undefined &&
    !Object.values(OTPChannel).includes(body.channel as OTPChannel)
  ) {
    throw new AuthError("Unsupported verification channel", 400);
  }
});

const validateForgotPassword = requireBody((body) => {
  const email = requireString(body, "email");
  validateEmail(email);
});

const validateResetPassword = requireBody((body) => {
  const email = requireString(body, "email");
  validateEmail(email);
  requireOtp(body);
  requireNewPassword(body, "newPassword");
});

const validateChangePassword = requireBody((body) => {
  const currentPassword = body.currentPassword;
  if (
    typeof currentPassword !== "string" ||
    !currentPassword ||
    Buffer.byteLength(currentPassword, "utf8") > 72
  ) {
    throw new AuthError("currentPassword is invalid", 400);
  }
  requireNewPassword(body, "newPassword");
});

export {
  validateChangePassword,
  validateForgotPassword,
  validateLogin,
  validateRegister,
  validateResendOtp,
  validateResetPassword,
  validateUserOtp,
};

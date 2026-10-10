import { NextFunction, Request, RequestHandler, Response } from "express";
import { AuthError } from "./auth.error";
import { requireAuth } from "./auth.middleware";
import { authService, toPublicUser } from "./auth.service";
import { OTPChannel } from "./otp/otp.model";

const asyncHandler =
  (
    handler: (req: Request, res: Response, next: NextFunction) => Promise<void>,
  ): RequestHandler =>
  (req, res, next) => {
    void handler(req, res, next).catch(next);
  };

const register = asyncHandler(async (req, res) => {
  const user = await authService.register(req.body);
  res.status(201).json({
    message: "Account created. A verification code has been sent.",
    user: toPublicUser(user),
  });
});

const verifyOTP = asyncHandler(async (req, res) => {
  const { email, otp } = req.body;
  const { user, tokens } = await authService.verifyAccount(email, otp);
  res.status(200).json({
    message: "Account verified successfully",
    user: toPublicUser(user),
    ...tokens,
  });
});

const resendOTP = asyncHandler(async (req, res) => {
  await authService.resendVerification(
    req.body.email,
    req.body.channel as OTPChannel | undefined,
  );
  res.status(200).json({
    message:
      "If an unverified account exists for that email, a verification code has been sent.",
  });
});

const login = asyncHandler(async (req, res) => {
  const { user, tokens } = await authService.login(
    req.body.email,
    req.body.password,
  );
  res.status(200).json({ user: toPublicUser(user), ...tokens });
});

const forgotPassword = asyncHandler(async (req, res) => {
  await authService.requestPasswordReset(req.body.email);
  res.status(202).json({
    message: "If an account exists for that email, a reset code has been sent.",
  });
});

const resetPasswordHandler = asyncHandler(async (req, res) => {
  const { email, otp, newPassword } = req.body;
  await authService.resetPassword(email, otp, newPassword);
  res.status(200).json({
    message: "Password reset successfully. Sign in again.",
  });
});

const changePassword = asyncHandler(async (req, res) => {
  const { userId } = requireAuth(req);
  await authService.changePassword(
    userId,
    req.body.currentPassword,
    req.body.newPassword,
  );
  res.status(200).json({
    message: "Password updated successfully. Sign in again.",
  });
});

const logout = asyncHandler(async (_req, res) => {
  res.status(204).send();
});

const getMe = asyncHandler(async (req, res) => {
  const { userId } = requireAuth(req);
  const user = await authService.getProfile(userId);
  res.status(200).json({ user: toPublicUser(user) });
});

export {
  changePassword,
  forgotPassword,
  getMe,
  login,
  logout,
  register,
  resendOTP,
  resetPasswordHandler,
  verifyOTP,
};

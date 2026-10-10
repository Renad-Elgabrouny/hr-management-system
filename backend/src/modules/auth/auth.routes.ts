import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import {
  changePassword,
  forgotPassword,
  getMe,
  login,
  logout,
  register,
  resendOTP,
  resetPasswordHandler,
  verifyOTP,
} from "./auth.controller";
import { authenticate } from "./auth.middleware";
import {
  validateChangePassword,
  validateForgotPassword,
  validateLogin,
  validateRegister,
  validateResendOtp,
  validateResetPassword,
  validateUserOtp,
} from "./auth.validation";

const router = Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { message: "Too many authentication requests. Try again later." },
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { message: "Too many verification requests. Try again later." },
});

router.post("/register", authLimiter, validateRegister, register);
router.post("/verify-otp", otpLimiter, validateUserOtp, verifyOTP);
router.post("/resend-otp", otpLimiter, validateResendOtp, resendOTP);
router.post("/login", authLimiter, validateLogin, login);
router.post(
  "/forgot-password",
  otpLimiter,
  validateForgotPassword,
  forgotPassword,
);
router.post(
  "/reset-password",
  otpLimiter,
  validateResetPassword,
  resetPasswordHandler,
);
router.post("/logout", logout);
router.get("/me", authenticate, getMe);
router.patch(
  "/change-password",
  authenticate,
  validateChangePassword,
  changePassword,
);

export default router;

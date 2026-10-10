import bcrypt from "bcryptjs";
import jwt, { SignOptions } from "jsonwebtoken";
import { env } from "../../config/env";
import { JWT_AUDIENCE, JWT_ISSUER, PASSWORD_SALT_ROUNDS } from "./auth.constants";
import { AuthError } from "./auth.error";
import { IUser, Role, UserModel } from "./auth.model";
import { OTPChannel, OTPPurpose } from "./otp/otp.model";
import { OTPService } from "./otp/otp.service";

interface IRegisterUser {
  email: string;
  password: string;
  phoneNumber?: string;
  channel: OTPChannel;
}

interface IAccessToken {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: string;
}

interface IAuthResult {
  user: IUser;
  tokens: IAccessToken;
}

interface IPublicUser {
  id: string;
  email: string;
  role: Role;
  isVerified: boolean;
  phoneNumber?: string;
}

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const isDuplicateKeyError = (error: unknown): boolean =>
  typeof error === "object" &&
  error !== null &&
  "code" in error &&
  error.code === 11000;

const toPublicUser = (user: IUser): IPublicUser => ({
  id: user._id.toString(),
  email: user.email,
  role: user.role,
  isVerified: user.isVerified,
  ...(user.phoneNumber ? { phoneNumber: user.phoneNumber } : {}),
});

class AuthService {
  constructor(private readonly otpService: OTPService) {}

  createAccessToken(user: IUser): IAccessToken {
    const accessToken = jwt.sign({ role: user.role }, env.JWT_SECRET, {
      subject: user._id.toString(),
      expiresIn: env.JWT_EXPIRES_IN as SignOptions["expiresIn"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    return {
      accessToken,
      tokenType: "Bearer",
      expiresIn: env.JWT_EXPIRES_IN,
    };
  }

  async register(userData: IRegisterUser): Promise<IUser> {
    const email = normalizeEmail(userData.email);
    const passwordHash = await bcrypt.hash(
      userData.password,
      PASSWORD_SALT_ROUNDS,
    );

    try {
      const user = await UserModel.create({
        email,
        hash_password: passwordHash,
        role: Role.EMPLOYEE,
        phoneNumber: userData.phoneNumber?.trim() || undefined,
        isVerified: false,
      });

      await this.otpService.sendOTP(
        user._id.toString(),
        userData.channel,
        OTPPurpose.ACCOUNT_VERIFICATION,
      );

      return user;
    } catch (error) {
      if (isDuplicateKeyError(error)) {
        throw new AuthError("An account with these details already exists", 409);
      }
      throw error;
    }
  }

  async verifyAccount(email: string, otp: string): Promise<IAuthResult> {
    const user = await this.requireUserByEmail(email);
    if (user.isVerified) {
      throw new AuthError("Account is already verified. Sign in instead.", 409);
    }

    await this.otpService.verifyOTP(
      user._id.toString(),
      otp,
      OTPPurpose.ACCOUNT_VERIFICATION,
    );
    user.isVerified = true;
    await user.save();

    return { user, tokens: this.createAccessToken(user) };
  }

  async resendVerification(
    email: string,
    requestedChannel?: OTPChannel,
  ): Promise<void> {
    const user = await UserModel.findOne({ email: normalizeEmail(email) });
    if (!user || user.isVerified) {
      return;
    }

    const channel =
      user.phoneNumber && requestedChannel === OTPChannel.SMS
        ? OTPChannel.SMS
        : OTPChannel.EMAIL;

    await this.otpService.sendOTP(
      user._id.toString(),
      channel,
      OTPPurpose.ACCOUNT_VERIFICATION,
    );
  }

  async login(emailInput: string, password: string): Promise<IAuthResult> {
    const user = await UserModel.findOne({
      email: normalizeEmail(emailInput),
    }).select("+hash_password");

    if (!user || !(await bcrypt.compare(password, user.hash_password))) {
      throw new AuthError("Invalid email or password", 401);
    }
    if (!user.isVerified) {
      throw new AuthError("Verify your account before signing in", 403);
    }

    return { user, tokens: this.createAccessToken(user) };
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await UserModel.findOne({
      email: normalizeEmail(email),
      isVerified: true,
    });
    if (!user) {
      return;
    }

    await this.otpService.sendOTP(
      user._id.toString(),
      OTPChannel.EMAIL,
      OTPPurpose.PASSWORD_RESET,
    );
  }

  async resetPassword(
    email: string,
    otp: string,
    newPassword: string,
  ): Promise<void> {
    const user = await UserModel.findOne({
      email: normalizeEmail(email),
      isVerified: true,
    }).select("+hash_password");
    if (!user) {
      throw new AuthError("Invalid or expired reset code", 400);
    }

    await this.otpService.verifyOTP(
      user._id.toString(),
      otp,
      OTPPurpose.PASSWORD_RESET,
    );
    user.hash_password = await bcrypt.hash(newPassword, PASSWORD_SALT_ROUNDS);
    await user.save();
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await UserModel.findById(userId).select("+hash_password");
    if (!user) {
      throw new AuthError("Account not found", 404);
    }
    if (!(await bcrypt.compare(currentPassword, user.hash_password))) {
      throw new AuthError("Current password is incorrect", 401);
    }

    user.hash_password = await bcrypt.hash(newPassword, PASSWORD_SALT_ROUNDS);
    await user.save();
  }

  async getProfile(userId: string): Promise<IUser> {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw new AuthError("User not found", 404);
    }
    return user;
  }

  private async requireUserByEmail(email: string): Promise<IUser> {
    const user = await UserModel.findOne({ email: normalizeEmail(email) });
    if (!user) {
      throw new AuthError("OTP is invalid, expired, or unavailable", 400);
    }
    return user;
  }
}

const authService = new AuthService(new OTPService());

export {
  AuthService,
  IAccessToken,
  IAuthResult,
  IPublicUser,
  IRegisterUser,
  authService,
  toPublicUser,
};

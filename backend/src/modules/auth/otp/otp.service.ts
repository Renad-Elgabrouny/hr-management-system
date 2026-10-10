import bcrypt from "bcryptjs";
import { Types } from "mongoose";
import { AuthError } from "../auth.error";
import { UserModel } from "../auth.model";
import { OTPChannel, OTPModel, OTPPurpose } from "./otp.model";
import { generateOTP } from "./otp.generator";
import { EmailOTPStrategy } from "./strategies/email-otp.strategy";
import { IOTPDeliveryStrategy } from "./strategies/otp-delivery.strategy";
import { SMSOTPStrategy } from "./strategies/sms-otp.strategy";

const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;

class OTPService {
  private readonly strategies = new Map<OTPChannel, IOTPDeliveryStrategy>();

  private getStrategy(channel: OTPChannel): IOTPDeliveryStrategy {
    let strategy = this.strategies.get(channel);
    if (!strategy && channel === OTPChannel.EMAIL) {
      strategy = new EmailOTPStrategy();
    } else if (!strategy && channel === OTPChannel.SMS) {
      strategy = new SMSOTPStrategy();
    }
    if (!strategy) {
      throw new AuthError("Unsupported OTP channel", 400);
    }
    this.strategies.set(channel, strategy);
    return strategy;
  }

  async sendOTP(
    userId: string,
    channel: OTPChannel,
    purpose: OTPPurpose,
  ): Promise<void> {
    if (!Types.ObjectId.isValid(userId)) {
      throw new AuthError("Invalid user identifier", 400);
    }

    const user = await UserModel.findById(userId);
    if (!user) {
      throw new AuthError("User not found", 404);
    }

    const destination =
      channel === OTPChannel.EMAIL ? user.email : user.phoneNumber;
    if (!destination) {
      throw new AuthError(
        "The selected verification channel is unavailable",
        400,
      );
    }

    const userObjectId = new Types.ObjectId(userId);
    const recentOtp = await OTPModel.exists({
      userId: userObjectId,
      purpose,
      createdAt: { $gt: new Date(Date.now() - RESEND_COOLDOWN_MS) },
    });
    if (recentOtp) {
      throw new AuthError("Please wait before requesting another OTP", 429);
    }

    const otp = generateOTP();
    const otpHash = await bcrypt.hash(otp, 10);
    await OTPModel.updateMany(
      { userId: userObjectId, purpose, consumed: false },
      { $set: { consumed: true } },
    );
    const otpRecord = await OTPModel.create({
      userId: userObjectId,
      otpHash,
      purpose,
      channel,
      expiresAt: new Date(Date.now() + OTP_TTL_MS),
      attempts: 0,
      consumed: false,
    });

    try {
      await this.getStrategy(channel).sendOTP(destination, otp);
    } catch {
      await OTPModel.deleteOne({ _id: otpRecord._id });
      throw new AuthError("Unable to deliver verification code", 503);
    }
  }

  async verifyOTP(
    userId: string,
    otp: string,
    purpose: OTPPurpose,
  ): Promise<void> {
    if (!Types.ObjectId.isValid(userId)) {
      throw new AuthError("Invalid user identifier", 400);
    }

    const userObjectId = new Types.ObjectId(userId);
    const otpRecord = await OTPModel.findOne({
      userId: userObjectId,
      purpose,
      consumed: false,
      expiresAt: { $gt: new Date() },
      attempts: { $lt: MAX_ATTEMPTS },
    }).sort({ createdAt: -1 });

    if (!otpRecord) {
      throw new AuthError("OTP is invalid, expired, or unavailable", 400);
    }

    const isValid = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!isValid) {
      const updated = await OTPModel.findOneAndUpdate(
        {
          _id: otpRecord._id,
          consumed: false,
          expiresAt: { $gt: new Date() },
          attempts: { $lt: MAX_ATTEMPTS },
        },
        { $inc: { attempts: 1 } },
        { new: true },
      );
      if (!updated || updated.attempts >= MAX_ATTEMPTS) {
        throw new AuthError("Too many OTP attempts", 429);
      }
      throw new AuthError("OTP is invalid, expired, or unavailable", 400);
    }

    const consumed = await OTPModel.findOneAndUpdate(
      {
        _id: otpRecord._id,
        consumed: false,
        expiresAt: { $gt: new Date() },
        attempts: { $lt: MAX_ATTEMPTS },
      },
      { $set: { consumed: true } },
      { new: true },
    );
    if (!consumed) {
      throw new AuthError("OTP is invalid, expired, or unavailable", 400);
    }
  }
}

export { OTPService };

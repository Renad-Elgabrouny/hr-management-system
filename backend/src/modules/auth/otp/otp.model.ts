import { model, Schema, Types } from "mongoose";

export enum OTPPurpose {
  ACCOUNT_VERIFICATION = "account_verification",
  PASSWORD_RESET = "password_reset",
}

export enum OTPChannel {
  EMAIL = "email",
  SMS = "sms",
}

export interface IOTP {
  userId: Types.ObjectId;
  otpHash: string;
  purpose: OTPPurpose;
  channel: OTPChannel;
  expiresAt: Date;
  attempts: number;
  consumed: boolean;
  createdAt: Date;
}

const otpSchema = new Schema<IOTP>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    otpHash: {
      type: String,
      required: true,
    },
    purpose: {
      type: String,
      enum: Object.values(OTPPurpose),
      required: true,
    },
    channel: {
      type: String,
      enum: Object.values(OTPChannel),
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    attempts: {
      type: Number,
      default: 0,
    },
    consumed: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true },
);

otpSchema.index({ userId: 1, purpose: 1, consumed: 1, createdAt: -1 });
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OTPModel = model<IOTP>("OTP", otpSchema);

export { OTPModel };

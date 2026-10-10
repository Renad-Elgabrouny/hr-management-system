import nodemailer from "nodemailer";
import { IOTPDeliveryStrategy } from "./otp-delivery.strategy";

class EmailOTPStrategy implements IOTPDeliveryStrategy {
  private transporter;

  constructor() {
    const auth = {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    };

    this.transporter = process.env.EMAIL_HOST
      ? nodemailer.createTransport({
          host: process.env.EMAIL_HOST,
          port: Number(process.env.EMAIL_PORT || 587),
          secure: process.env.EMAIL_SECURE === "true",
          auth,
        })
      : nodemailer.createTransport({
          service: process.env.EMAIL_SERVICE || "gmail",
          auth,
        });
  }

  async sendOTP(destination: string, otp: string): Promise<void> {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      throw new Error("Email delivery is not configured");
    }

    await this.transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: destination,
      subject: "HR Management System - OTP Verification",
      text: `Your verification code is ${otp}. It will expire in 5 minutes. If you did not request this code, you can ignore this email.`,
    });
  }
}

export { EmailOTPStrategy };

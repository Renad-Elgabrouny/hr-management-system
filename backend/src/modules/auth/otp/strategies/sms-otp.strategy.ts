import twilio from "twilio";
import { IOTPDeliveryStrategy } from "./otp-delivery.strategy";

class SMSOTPStrategy implements IOTPDeliveryStrategy {
  private client;

  constructor() {
    if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN) {
      throw new Error("SMS delivery is not configured");
    }
    this.client = twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN,
    );
  }

  async sendOTP(destination: string, otp: string): Promise<void> {
    if (!process.env.TWILIO_PHONE_NUMBER) {
      throw new Error("SMS delivery is not configured");
    }
    await this.client.messages.create({
      body: `Your HR Management System OTP is ${otp}. It will expire in 5 minutes.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: destination,
    });
  }
}

export { SMSOTPStrategy };

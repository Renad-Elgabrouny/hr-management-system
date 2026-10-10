export interface IOTPDeliveryStrategy {
  sendOTP(destination: string, otp: string): Promise<void>;
}
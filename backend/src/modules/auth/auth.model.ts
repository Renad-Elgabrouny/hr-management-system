import { Document, Schema, model } from "mongoose";

enum Role {
  ADMIN = "admin",
  HR_MANAGER = "hr_manager",
  MANAGER = "manager",
  SECURITY_OFFICER = "security_officer",
  EMPLOYEE = "employee",
}

interface IUser extends Document {
  email: string;
  hash_password: string;
  role: Role;
  isVerified: boolean;
  phoneNumber?: string;
}

const userSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    hash_password: {
      type: String,
      required: true,
      select: false,
    },
    role: {
      type: String,
      enum: Object.values(Role),
      required: true,
      default: Role.EMPLOYEE,
    },
    isVerified: {
      type: Boolean,
      default: false,
      index: true,
    },
    phoneNumber: {
      type: String,
      unique: true,
      sparse: true,
      trim: true,
    },
  },
  { timestamps: true },
);

const UserModel = model<IUser>("User", userSchema);

const isRole = (value: unknown): value is Role =>
  Object.values(Role).includes(value as Role);

export { IUser, Role, UserModel, isRole };

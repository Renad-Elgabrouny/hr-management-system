import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import morgan from "morgan";
import { AuthError } from "./modules/auth/auth.error";
import authRoutes from "./modules/auth/auth.routes";

const app = express();

app.use(helmet());
app.use(cors());
app.use(morgan("dev"));
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/api/auth", authRoutes);

app.use((_req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.use(
  (error: unknown, _req: Request, res: Response, next: NextFunction): void => {
    if (res.headersSent) {
      next(error);
      return;
    }
    if (error instanceof AuthError) {
      res.status(error.statusCode).json({ message: error.message });
      return;
    }
    console.error("Unhandled application error");
    res.status(500).json({ message: "An unexpected error occurred" });
  },
);

export default app;

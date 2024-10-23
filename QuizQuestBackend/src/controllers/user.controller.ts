import { Request, Response, NextFunction } from "express";
import userModel, { IUser } from "../models/user.model";
import ErrorHandler from "../utils/errorHandler";
import { CatchAsyncError } from "../middleware/catchAsyncErrors";
import jwt, { JwtPayload, Secret } from "jsonwebtoken";
import ejs from "ejs";
import path from "path";
import sendEmail from "../utils/sendMail";
import cloudinary from "cloudinary";
import {
  accessTokenOptions,
  refreshTokenOptions,
  sendToken,
} from "../config/jwt";

import { redis } from "../config/redis";
require("dotenv").config();

export const updateUserInfo = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, email } = req.body as IUpdateUserInfo;
      const userId = req.user?._id;
      const user = await userModel.findById(userId);

      if (email && user) {
        const existEmail = await userModel.findOne({ email });
        if (existEmail && existEmail.email !== user.email) {
          return next(new ErrorHandler("Email already exists", 400));
        }
        user.email = email;
      }
      if (name && user) {
        user.username = name;
      }

      await user?.save();
      await redis.set(userId as string, JSON.stringify(user));
      res.status(200).json({
        success: true,
        message: "User updated successfully",
        user,
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

interface IUpdatePassword {
  oldPassword: string;
  newPassword: string;
}
export const updatePassword = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { oldPassword, newPassword } = req.body as IUpdatePassword;
      if (!oldPassword || !newPassword) {
        return next(new ErrorHandler("Please enter old and new password", 400));
      }

      const user = await userModel.findById(req.user?.id).select("+password");
      if (user?.password === undefined) {
        return next(
          new ErrorHandler("Please login to access this resource", 401)
        );
      }
      const isPasswordMatched = await user?.comparePassword(oldPassword);
      if (!isPasswordMatched) {
        return next(new ErrorHandler("Incorrect password sus", 400));
      }
      user!.password = newPassword;
      await user?.save();
      await redis.set(user?._id as string, JSON.stringify(user));
      res.status(200).json({
        success: true,
        message: "Password updated successfully",
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);
interface IProfilePicture {
  avatar: string;
}

export const updateAccessToken = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      console.log("Attempting to refresh token");
      const refresh_token = req.cookies.refreshToken as string;
      console.log("refresh_token:", refresh_token);

      // If there's no refresh token, request login
      if (!refresh_token) {
        return next(
          new ErrorHandler("Please login to access this resource", 401)
        );
      }

      let decoded: JwtPayload;

      try {
        // Wrap jwt.verify in try-catch to handle malformed tokens
        decoded = jwt.verify(
          refresh_token,
          process.env.REFRESH_TOKEN as string
        ) as JwtPayload;
      } catch (err) {
        return next(new ErrorHandler("Invalid refresh token", 403));
      }

      const session = await redis.get(decoded.id as string);

      if (!session) {
        return next(new ErrorHandler("Session expired or invalid", 400));
      }

      const user = JSON.parse(session);
      if (!user) {
        return next(new ErrorHandler("User not found", 404));
      }

      // Create new tokens
      const accessToken = jwt.sign(
        { id: user.id },
        process.env.ACCESS_TOKEN as string,
        { expiresIn: "5m" }
      );
      const refreshToken = jwt.sign(
        { id: user.id },
        process.env.REFRESH_TOKEN as string,
        { expiresIn: "7d" }
      );

      // Set tokens in cookies
      res.cookie("accessToken", accessToken, accessTokenOptions);
      res.cookie("refreshToken", refreshToken, refreshTokenOptions);

      // Update session in Redis with new expiration
      await redis.set(user._id, JSON.stringify(user), "EX", 60 * 60 * 24 * 7); // 7 days

      res.status(200).json({
        success: true,
        accessToken,
      });
    } catch (error: any) {
      console.error("Error in token refresh process:", error);
      return next(new ErrorHandler(error.message, 500));
    }
  }
);

interface IUpdateUserInfo {
  name: string;
  email: string;
}

import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import * as yup from "yup";
import { useDispatch, useSelector } from "react-redux";
import { Radio } from "react-loader-spinner";
import { toast } from "react-toastify";
import DoWellVerticalLogo from "../assets/images/Dowell-logo-Vertical.jpeg";
import { forgotPasswordAsync, sendOTP } from "../redux/forgotPasswordSlice";
import PasswordInput from "./passwordInput";

const schema = yup.object().shape({
  username: yup
    .string()
    .required("User Name is required")
    .max(20)
    .notOneOf(
      ["administrator", "uxlivinglab", "dowellresearch", "dowellteam", "admin"],
      "Username not allowed"
    ),
  email: yup
    .string()
    .email("Invalid email format")
    .required("Email is required"),
  otp: yup
    .string()
    .required("OTP is required")
    .matches(/^[0-9]+$/, "OTP must contain only numbers"),
  new_password: yup
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(99)
    .required("Password is required"),
  confirm_password: yup
    .string()
    .oneOf([yup.ref("new_password")], "Passwords must match")
    .required("Confirm Password is required"),
});

const ForgotPassword = () => {
  const [attemptsOtp, setAttemptsOtp] = useState(5);
  const [otpCountdown, setOtpCountdown] = useState(0);

  const dispatch = useDispatch();
  const { otpLoading, pwLoading, otpSent, passwordReset, error } =
    useSelector((state) => state.forgotPassword) || {};

  const conditionalSchema = otpSent
    ? schema
    : yup.object().shape({
        username: yup
          .string()
          .required("User Name is required")
          .max(20)
          .notOneOf(
            [
              "administrator",
              "uxlivinglab",
              "dowellresearch",
              "dowellteam",
              "admin",
            ],
            "Username not allowed"
          ),
        email: yup
          .string()
          .email("Invalid email format")
          .required("Email is required"),
      });

  const {
    handleSubmit,
    register,
    formState: { errors },
    setValue,
    getValues,
    watch,
    reset,
  } = useForm({ resolver: yupResolver(conditionalSchema) });

  const handleSendOTP = (data) => {
    if (attemptsOtp > 0) {
      setAttemptsOtp((prevAttempts) => prevAttempts - 1);
      const { username, email } = data;
      if (username && email) {
        dispatch(sendOTP({ username, email, usage: "forgot_password" }));
        setOtpCountdown(60);
      }
    }
  };

  // password reset handler
  const handleForgotPassword = (data) => {
    const { username, email, otp, new_password, confirm_password } = data;
    if (otp && new_password && confirm_password) {
      dispatch(
        forgotPasswordAsync({
          username,
          email,
          otp,
          new_password,
          confirm_password,
        })
      );
    }
  };

  // Countdown timer for OTP
  useEffect(() => {
    if (otpCountdown > 0) {
      const otpTimer = setTimeout(() => {
        setOtpCountdown((prevCountdown) => prevCountdown - 1);
      }, 1000); // 1 second
      return () => clearTimeout(otpTimer);
    }
  }, [otpCountdown]);

  //  Use useEffect to show success and error messages using react-toastify
  useEffect(() => {
    const showToast = (message, isSuccess = false) => {
      if (message && !otpLoading && !pwLoading) {
        isSuccess ? toast.success(message) : toast.error(message);
      }
    };

    // Show toasts only if passwordReset is false
    if (!passwordReset) {
      showToast(otpSent, true);
    }

    showToast(passwordReset, true);
    showToast(error);
  }, [otpSent, passwordReset, error, otpLoading, pwLoading]);

  return (
    <div className="isolate px-2 py-4 sm:py-12 lg:px-8">
      <div className="shadow-sm  mx-auto max-w-5xl px-2 py-6 md:px-4">
        <div className="flex items-center justify-center">
          <div className="text-center space-y-2">
            <img
              src={DoWellVerticalLogo}
              alt="DoWell logo"
              className="h-34 w-44 rounded-sm drop-shadow-md mx-auto"
            />
            <h2 className="text-xl font-semibold tracking-wide text-green-500 md:text-2xl">
              Forgot Password
            </h2>
            <div className="flex text-gray-600 py-2 text-left space-x-2">
              <p>Do you forgot your username?</p>
              <Link to="/forgot_username">
                <span className="text-green-600">Click here</span>
              </Link>
            </div>
          </div>
        </div>

        <form
          className="mx-auto mt-8 max-w-xl sm:mt-12"
          onSubmit={handleSubmit(handleForgotPassword)}
        >
          <div>
            <label htmlFor="username" className="label">
              Username <span className="text-red-500">*</span>
            </label>
            <div className="mt-2.5">
              <input
                type="text"
                name="username"
                id="username"
                placeholder="Enter Your Username"
                autoComplete="username"
                className="input-field"
                {...register("username")}
              />
              {errors.username && (
                <p className="text-red-500 text-xs mt-1">
                  {errors.username.message}
                </p>
              )}
            </div>
          </div>

          <div className="mt-2.5">
            <label htmlFor="email" className="label">
              Email <span className="text-red-500">*</span>
            </label>
            <div className="mt-2.5">
              <input
                type="email"
                name="email"
                id="email"
                placeholder="Enter Your Email"
                autoComplete="email"
                className="input-field"
                {...register("email")}
              />
              {errors.email && (
                <p className="text-red-500 text-xs mt-1">
                  {errors.email.message}
                </p>
              )}
            </div>
            <div className="mt-2.5">
              <div className="flex flex-row space-x-3 items-center">
                <button
                  className="btn-send px-2 py-1 self-start"
                  onClick={() => handleSendOTP(watch())}
                  disabled={
                    otpLoading || (otpSent && otpCountdown) || attemptsOtp === 0
                  }
                >
                  {otpLoading ? (
                    <Radio
                      visible={true}
                      height={30}
                      width={30}
                      ariaLabel="radio-loading"
                      wrapperStyle={{}}
                      wrapperClassName="radio-wrapper"
                      color="#1ff507"
                    />
                  ) : (
                    "Get OTP"
                  )}
                </button>
              </div>

              {/* Display the countdown timer only after the first OTP attempt */}
              {otpSent && otpCountdown > 0 && !error && (
                <div className="text-base font-normal text-green-600">
                  Resend OTP in: {otpCountdown}s
                </div>
              )}

              {/* Display the email OTP attempts remaining */}
              {attemptsOtp > 0 && otpSent && !error && (
                <div>
                  <p className="text-base font-normal text-green-600">
                    Attempts remaining: {attemptsOtp}
                  </p>
                </div>
              )}

              {/* Display checkbox to exempt from email OTP */}
              {attemptsOtp === 0 && otpCountdown === 0 && (
                <div className="text-sm leading-6">
                  <p className="text-red-600">
                    You have to reload the page and try again!!
                  </p>
                </div>
              )}
            </div>
          </div>

          <div className="mt-2.5">
            <label className="label" htmlFor="otp">
              Enter OTP from Email <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              name="otp"
              id="otp"
              placeholder="Enter OTP from Email"
              autoComplete="otp"
              className="input-field"
              {...register("otp")}
            />
            {errors.otp && (
              <p className="text-red-500 text-xs mt-1">{errors.otp.message}</p>
            )}
          </div>

          <div className="mt-2">
            <PasswordInput
              name="new_password"
              register={register}
              value={getValues("new_password")}
              errors={errors}
              isConfirm={false}
              onChange={setValue}
            />
          </div>

          <div className="mt-2">
            <PasswordInput
              name="confirm_password"
              register={register}
              value={getValues("confirm_password")}
              errors={errors}
              isConfirm={true}
              onChange={setValue}
            />
          </div>

          <div className="mt-4">
            <button type="submit" className="submit-btn" disabled={pwLoading}>
              {pwLoading ? (
                <Radio
                  visible={true}
                  height={30}
                  width={30}
                  ariaLabel="radio-loading"
                  wrapperStyle={{}}
                  wrapperClassName="radio-wrapper"
                  color="#1ff507"
                />
              ) : (
                "Change Password"
              )}
            </button>
          </div>

          <div className="flex items-center justify-center">
            <div className="w-60 rounded-md bg-green-300 py-2.5 mt-6 text-white shadow-sm hover:bg-green-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-700 text-center">
              <Link to="/">Do have an account? Log in</Link>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ForgotPassword;

import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { postData } from "./instance";

export const userSendOTP = createAsyncThunk(
  "forgotUsername/userSendOTP",
  async ({ email, usage }) => {
    const response = await postData("/api/emailotp/", {
      email,
      usage,
    });
    return response;
  }
);

export const verifyOTP = createAsyncThunk(
  "forgotUsername/verifyOTP",
  async ({ email, otp }) => {
    const response = await postData("/api/forgot_username/", {
      email,
      otp,
    });
    return response;
  }
);

const forgotUsernameSlice = createSlice({
  name: "forgotUsername",
  initialState: {
    otpLoading: false,
    vfyLoading: false,
    usernameList: "",
    otpSent: false,
    error: null,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(userSendOTP.pending, (state) => {
        state.otpLoading = true;
        state.error = null;
      })
      .addCase(userSendOTP.fulfilled, (state, action) => {
        state.otpLoading = false;
        state.otpSent = action.payload; // Update otpSent with the received value
      })
      .addCase(userSendOTP.rejected, (state, action) => {
        state.otpLoading = false;
        state.error = action.error.message;
      })
      .addCase(verifyOTP.pending, (state) => {
        state.vfyLoading = true;
        state.error = null;
      })
      .addCase(verifyOTP.fulfilled, (state, action) => {
        state.vfyLoading = false;
        state.usernameList = action.payload; // Update usernameList with the received value
      })
      .addCase(verifyOTP.rejected, (state, action) => {
        state.vfyLoading = false;
        state.error = action.error.message;
      });
  },
});

export default forgotUsernameSlice.reducer;

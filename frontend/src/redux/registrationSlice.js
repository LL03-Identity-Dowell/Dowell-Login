import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import axios from "axios";

const base_url = "https://100014.pythonanywhere.com";

// Async thunk function to handle the email OTP request.
export const sendEmailOTP = createAsyncThunk(
  "registration/sendEmailOTP",
  async ({ username, email, usage }) => {
    try {
      const response = await axios.post(`${base_url}/api/emailotp/`, {
        username,
        email,
        usage,
      });
      if (response.data.msg === "success") {
        return response.data.info;
      }
    } catch (error) {
      throw new Error(error.response.data.info);
    }
  }
);

// Async thunk function to handle the mobile OTP request
export const sendMobileOTP = createAsyncThunk(
  "registration/sendMobileOTP",
  async ({ phonecode, Phone }) => {
    try {
      const response = await axios.post(`${base_url}/api/mobilesms/`, {
        phonecode,
        Phone,
      });
      if (response.data.msg === "success") {
        return response.data.info;
      }
    } catch (error) {
      throw new Error(error.response.data.info);
    }
  }
);

// Async thunk to handle registration API call
export const registerUser = createAsyncThunk(
  "registration/registerUser",
  async (formData) => {
    try {
      const response = await axios.post(`${base_url}/api/register/`, formData);
      if (response?.data.msg === "success") {
        return response?.data.info;
      }
    } catch (error) {
      throw new Error(error.response?.data.info);
    }
  }
);

// Create the registration slice
const registrationSlice = createSlice({
  name: "registration",
  initialState: {
    otpLoading: false,
    smsLoading: false,
    regLoading: false,
    registered: false,
    otpSent: false,
    smsSent: false,
    error: null,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(sendEmailOTP.pending, (state) => {
        state.otpLoading = true;
        state.error = null;
      })
      .addCase(sendEmailOTP.fulfilled, (state, action) => {
        state.otpLoading = false;
        state.otpSent = action.payload;
      })
      .addCase(sendEmailOTP.rejected, (state, action) => {
        state.otpLoading = false;
        state.error = action.error.message;
      })
      .addCase(sendMobileOTP.pending, (state) => {
        state.smsLoading = true;
        state.error = null;
      })
      .addCase(sendMobileOTP.fulfilled, (state, action) => {
        state.smsLoading = false;
        state.smsSent = action.payload;
      })
      .addCase(sendMobileOTP.rejected, (state, action) => {
        state.smsLoading = false;
        state.error = action.error.message;
      })
      .addCase(registerUser.pending, (state) => {
        state.regLoading = true;
        state.error = null;
      })
      .addCase(registerUser.fulfilled, (state, action) => {
        state.regLoading = false;
        state.registered = action.payload;
      })
      .addCase(registerUser.rejected, (state, action) => {
        state.regLoading = false;
        state.error = action.error.message;
      });
  },
});

export default registrationSlice.reducer;

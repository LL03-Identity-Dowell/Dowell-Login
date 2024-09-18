import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

const api_url = "https://100014.pythonanywhere.com/api/main_login/";
const link_login_api = "https://100014.pythonanywhere.com/api/master_login/";
const voice_login_api = "https://100014.pythonanywhere.com/api/voice_api/";
export const loginUser = createAsyncThunk(
  "login/loginUser",
  async ({
    username,
    password,
    time,
    ip,
    os,
    device,
    location,
    timezone,
    language,
    browser,
    mainparams,
    randomSession,
    redirectUrl,
  }) => {
    try {
      const response = await axios.post(api_url, {
        username,
        password,
        time,
        ip,
        os,
        device,
        location,
        timezone,
        language,
        browser,
        mainparams,
        randomSession,
        redirectUrl,
      });

      if (response?.data.msg === "success") {
        return response?.data;
      }
    } catch (error) {
      throw new Error(error.response?.data.info);
    }
  }
);
export const linkLogin = createAsyncThunk(
  "login/linklogin",
  async ({
    time,
    ip,
    os,
    device,
    location,
    timezone,
    language,
    browser,
    mainparams,
  }) => {
    try {
      const response = await axios.post(link_login_api, {
        time,
        ip,
        os,
        device,
        location,
        timezone,
        language,
        browser,
        mainparams,
      });
      if (response?.data.msg === "success") {
        return response?.data;
      }
    } catch (error) {
      throw new Error(error.response?.data.info);
    }
  }
);
export const voiceLogin = createAsyncThunk(
  "login/voiceLogin",
  async ({
    time,
    ip,
    os,
    device,
    location,
    timezone,
    language,
    browser,
    data,
    voiceData,
    randomSession,
    redirectUrl,
  }) => {
    try {
      const response = await axios.post(voice_login_api, {
        time,
        ip,
        os,
        device,
        location,
        timezone,
        language,
        browser,
        data,
        file: voiceData,
        randomSession,
        redirectUrl,
      });
      if (response?.data.msg === "success") {
        return response?.data;
      }
    } catch (error) {
      throw new Error(error.response?.data.info);
    }
  }
);

// Create the authentication slice
const loginSlice = createSlice({
  name: "login",
  initialState: {
    userInfo: null,
    loading: false,
    error: null,
  },
  reducers: {
    reset: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.userInfo = action.payload;
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      .addCase(linkLogin.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(linkLogin.fulfilled, (state, action) => {
        state.loading = false;
        state.userInfo = action.payload;
      })
      .addCase(linkLogin.rejected, (state, action) => {
        state.loading = false;
        state.error = true;
      })
      .addCase(voiceLogin.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(voiceLogin.fulfilled, (state, action) => {
        state.loading = false;
        state.userInfo = action.payload;
      })
      .addCase(voiceLogin.rejected, (state, action) => {
        state.loading = false;
        state.error = true;
      });
  },
});

export const { reset } = loginSlice.actions;
export default loginSlice.reducer;

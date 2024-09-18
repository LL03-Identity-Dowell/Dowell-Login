import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import axios from "axios";

const base_url = "https://100014.pythonanywhere.com";

// Async thunk to change the password
export const changePasswordAsync = createAsyncThunk(
  "changePassword/changePasswordAsync",
  async ({ username, old_password, new_password }) => {
    try {
      const response = await axios.post(`${base_url}/api/password_change/`, {
        username,
        old_password,
        new_password,
      });
      if (response.data.msg === "success") {
        return response.data.info;
      }
    } catch (error) {
      throw new Error(error.response.data.info);
    }
  }
);

const passwordSlice = createSlice({
  name: "changePassword",
  initialState: {
    loading: false,
    changePassword: false,
    error: null,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(changePasswordAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(changePasswordAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.changePassword = action.payload;
      })
      .addCase(changePasswordAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      });
  },
});

export default passwordSlice.reducer;

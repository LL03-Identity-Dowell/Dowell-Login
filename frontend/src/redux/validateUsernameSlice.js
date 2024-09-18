import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import axios from "axios";

const base_url = "https://100014.pythonanywhere.com";

export const validateUsernameAsync = createAsyncThunk(
  "validateUsername/validateUsernameAsync",
  async (username) => {
    try {
      const response = await axios.post(`${base_url}/api/validate_username/`, {
        username,
      });
      return response.data.info;
    } catch (error) {
      throw new Error(error.response.data.info);
    }
  }
);

const validateUsernameSlice = createSlice({
  name: "validateUsername",
  initialState: {
    isLoading: false,
    isUsernameAvailable: null,
    isError: null,
  },
  reducers: {
    resetUsernameAvailability: (state) => {
      state.isUsernameAvailable = null;
    },
    resetUsernameError: (state) => {
      state.isError = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(validateUsernameAsync.pending, (state) => {
        state.isLoading = true;
        state.isUsernameAvailable = null;
      })
      .addCase(validateUsernameAsync.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isUsernameAvailable = action.payload;
      })
      .addCase(validateUsernameAsync.rejected, (state, action) => {
        state.isLoading = false;
        state.isError = action.error.message;
      });
  },
});

export const { resetUsernameAvailability, resetUsernameError } =
  validateUsernameSlice.actions;

export default validateUsernameSlice.reducer;

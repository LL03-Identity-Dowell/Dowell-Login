import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { postData } from "./instance";

// Create an async thunk for the logout API call
export const logoutUser = createAsyncThunk(
  "logout/logoutUser",
  async ({ session_id }) => {
    const response = await postData("/api/main_logout/", { session_id });
    return response;
  }
);

// Create the logout slice
const logoutSlice = createSlice({
  name: "logout",
  initialState: {
    loading: false,
    error: null,
    loggedOut: false,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(logoutUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(logoutUser.fulfilled, (state, action) => {
        state.loading = false;
        state.loggedOut = action.payload;
      })
      .addCase(logoutUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      });
  },
});

export default logoutSlice.reducer;

import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

const api_url = "https://100014.pythonanywhere.com/api/login_init_api/";

// Async Thunks
export const initSessionID = createAsyncThunk(
  "init/initSessionID",
  async ({ mainparams, redirectUrl }) => {
    try {
      const response = await axios.post(api_url, { mainparams, redirectUrl });
      return response?.data;
    } catch (error) {
      throw new Error("Error generating init session ID:", error);
    }
  }
);

// Create the init slice
const initSlice = createSlice({
  name: "init",
  initialState: {
    initSession: "",
    isLoading: false,
    error: null,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(initSessionID.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(initSessionID.fulfilled, (state, action) => {
        state.isLoading = false;
        state.initSession = action.payload;
      })
      .addCase(initSessionID.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.error.message;
      });
  },
});

export default initSlice.reducer;

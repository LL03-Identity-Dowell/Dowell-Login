import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import axios from "axios";

export const fetchCountries = createAsyncThunk(
  "countries/fetchCountries",
  async () => {
    const response = await axios.get(
      `https://100074.pythonanywhere.com/countries/johnDoe123/haikalsb1234/100074`
    );
    return response.data;
  }
);

// countries slice
const countriesSlice = createSlice({
  name: "countries",
  initialState: [],
  reducers: {},
  extraReducers: (builder) => {
    builder.addCase(fetchCountries.fulfilled, (state, action) => {
      return action.payload;
    });
  },
});

export default countriesSlice.reducer;

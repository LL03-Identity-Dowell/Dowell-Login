import { configureStore } from "@reduxjs/toolkit";
import countriesReducer from "./countriesSlice";
import loginReducer from "./loginSlice";
import registrationReducer from "./registrationSlice";
import logoutReducer from "./logoutSlice";
import changePasswordReducer from "./changePasswordSlice";
import initSliceReducer from "./initSlice";
import forgotPasswordReducer from "./forgotPasswordSlice";
import forgotUsernameSlice from "./forgotUsernameSlice";
import validateUsernameReducer from "./validateUsernameSlice";
import faceLoginReducer from "./faceLoginSlice";

const store = configureStore({
  reducer: {
    countries: countriesReducer,
    forgotPassword: forgotPasswordReducer,
    forgotUsername: forgotUsernameSlice,
    login: loginReducer,
    registration: registrationReducer,
    logout: logoutReducer,
    changePassword: changePasswordReducer,
    init: initSliceReducer,
    validateUsername: validateUsernameReducer,
    faceLogin: faceLoginReducer,
  },
});

export default store;

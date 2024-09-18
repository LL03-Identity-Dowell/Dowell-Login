import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { RotatingLines } from "react-loader-spinner";
import Iframe from "react-iframe";
import { toast } from "react-toastify";
import mobileCoordinate from "../utils/mobileCoordinate";
import { loginUser } from "../redux/loginSlice";
import { detectBrowser } from "../utils/browserUtils";
import { getOperatingSystem, getDeviceType } from "../utils/deviceUtils";
import LanguageDropdown from "./LanguageDropdown";
import Coordinate from "../utils/Coordinate";
import Timer from "../assets/images/count_up.gif";

const MobileLog = () => {
  const [userLanguage, setUserLanguage] = useState("en");
  const [showTimer, setShowTimer] = useState(false);
  const [username, setUsername] = useState("");
  const [redirecting, setRedirecting] = useState(false);

  const { userInfo, loading, error } =
    useSelector((state) => state.login) || {};

  // Get the random session ID from the Redux store
  const { initSession } = useSelector((state) => state.init);
  const randomSession = initSession.random_session;

  // Access the dispatch function
  const dispatch = useDispatch();

  const time = new Date().toLocaleTimeString();
  const os = getOperatingSystem();
  const device = getDeviceType();
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const browser = detectBrowser();

  // Get the query parameters
  const urlString = window.location.href;
  const paramString = urlString.split("?")[1];
  const queryString = new URLSearchParams(paramString);
  const query = queryString.toString();

  // Check if there are query parameters before proceeding
  const mainparams = query
    ? Array.from(queryString.entries())
        .map(([key, value]) => `${key}=${value}`)
        .join("&")
    : "";

  // Use the useLocation hook to access the URL parameters
  const locationParams = useLocation();
  const queryParams = new URLSearchParams(locationParams.search);

  // Extract the redirect_url parameter from the query parameters
  const redirectUrl = queryParams.get("redirect_url");

  // Handle user information
  const handleUserInfo = async (e) => {
    e.preventDefault();
    try {
      const location = await mobileCoordinate();
      const { username, password } = e.target.elements;
      // update the username state
      setUsername(username.value);

      const userData = {
        username: username.value,
        password: password.value,
        time,
        ip: "",
        os,
        device,
        timezone,
        language: userLanguage,
        browser,
        location,
        randomSession,
        mainparams,
        redirectUrl,
      };

      const response = await dispatch(loginUser(userData));
      const sessionID = response?.payload?.session_id;
      const URL = response?.payload?.url;

      if (sessionID) {
        // Set the redirecting state to true
        setRedirecting(true);

        // Redirect to specific url
        window.location.href = URL;
      }
    } catch (error) {
      const { username, password } = e.target.elements;
      // update the username state
      setUsername(username.value);

      const userData = {
        username: username.value,
        password: password.value,
        time,
        ip: "",
        os,
        device,
        timezone,
        language: userLanguage,
        browser,
        location: "",
        randomSession,
        mainparams,
        redirectUrl,
      };

      const response = await dispatch(loginUser(userData));
      const sessionID = response?.payload?.session_id;
      const URL = response?.payload?.url;

      if (sessionID) {
        // Set the redirecting state to true
        setRedirecting(true);

        // Redirect to specific url
        window.location.href = URL;
      }
      console.log(error);
      //throw new Error(error.response.data.info);
    }
  };

  // Handle language change
  const handleLanguageChange = (language) => {
    setUserLanguage(language);
  };

  // use setTimeout to hide the timer after 10 seconds
  useEffect(() => {
    const timer = setTimeout(() => {
      setShowTimer(true);
    }, 1000);

    // Cleanup the timer when component unmounts or loading is complete
    return () => clearTimeout(timer);
  }, []);

  // Iframe URL
  const iframeURL = () => {
    const url = `https://100014.pythonanywhere.com/check_status?username=${username}`;
    return url;
  };

  // Use useEffect to show success and error messages using react-toastify
  useEffect(() => {
    if (userInfo) {
      toast.success(userInfo);
    } else {
      toast.error(error);
    }
  }, [userInfo, error]);

  return (
    <>
      {loading || redirecting ? (
        <div className="w-full items-center justify-center rounded-xl mt-0 bg-gray-50">
          <div className="flex flex-col w-full rounded-xl shadow-lg text-gray-500 overflow-hidden">
            <div className="relative w-32 h-32 md:w-48 md:h-48 mx-auto">
              {/* Spinner */}
              <div className="absolute top-0 left-0 w-full h-full flex justify-center items-center z-10">
                <RotatingLines
                  visible={true}
                  height={96}
                  width={96}
                  ariaLabel="radio-loading"
                  wrapperStyle={{}}
                  color="#1ff507"
                  strokeWidth="5"
                />
              </div>

              {/* Timer (background) */}
              {showTimer && (
                <div className="absolute inset-0 flex items-center justify-center">
                  <img src={Timer} alt="Loading timer" className="w-10 h-8" />
                </div>
              )}
            </div>

            <div className="">
              <Iframe
                url={iframeURL()}
                className="py-1 w-full h-[192px] md:h-[250px]"
                id="myiFrame"
              />
            </div>
          </div>
        </div>
      ) : (
        <div className="flex w-full items-center justify-center border border-solid border-gray-600 rounded-xl mt-0">
          <div
            className="flex flex-col justify-between md:flex-row bg-yellow-50
           w-full max-w-3xl rounded-xl shadow-lg text-gray-500 overflow-hidden"
          >
            <div className="flex flex-col md:w-60 p-4 space-y-8 bg-gradient-to-r from-yellow-50 to-gray-50">
              <h2 className="text-2xl bg-green-600 bg-clip-text text-transparent">
                Member Login
              </h2>

              <div className="flex flex-col space-y-2">
                <p className=" text-gray-500 text-base">
                  Do not remember username or password?
                </p>
                <Link to="/forgot_password">
                  <span className="text-green-500 text-base">Click here</span>
                </Link>
              </div>

              <div className="text-gray-500 text-base">
                <p>Don't have an account?</p>
                <Link to={`/register?${mainparams}`}>
                  <span className="text-green-500 text-base">Sign up</span>
                </Link>
              </div>
            </div>

            <div className="relative md:w-96">
              <div className="z-10 bg-yellow-50 rounded-xl drop-shadow-sm p-4 text-gray-700 border border-solid border-green-200 space-y-2">
                <div className="flex flex-col space-y-2 px-2 w-auto">
                  <p className="label">Select your language</p>
                  <LanguageDropdown
                    selectedLanguage={userLanguage}
                    onLanguageChange={handleLanguageChange}
                  />
                </div>

                <form
                  className="flex flex-col space-y-4 p-4 shadow-lg shadow-slate-400"
                  onSubmit={handleUserInfo}
                >
                  <div>
                    <label htmlFor="username" className="label">
                      User Name <span className="text-red-500">*</span>
                    </label>
                    <div className="mt-2.5">
                      <input
                        type="text"
                        name="username"
                        id="username"
                        placeholder="Enter Your Username"
                        autoComplete="username"
                        className="input-field"
                      />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="password" className="label">
                      Password<span className="text-red-500">*</span>
                    </label>
                    <div className="mt-2.5">
                      <input
                        type="password"
                        name="password"
                        id="password"
                        placeholder="Enter Your Password"
                        autoComplete="password"
                        className="input-field"
                      />
                    </div>
                  </div>

                  <div className="mt-4">
                    <button
                      type="submit"
                      className="submit-btn"
                      disabled={loading}
                    >
                      Login
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default MobileLog;

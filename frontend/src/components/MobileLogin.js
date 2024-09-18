import React, { useEffect, useState } from "react";
import MyMobileTabs from "./MyMobileTabs";
import { useDispatch, useSelector } from "react-redux";
import { initSessionID } from "../redux/initSlice";
import { Radio } from "react-loader-spinner";
import { Navigate, useLocation } from "react-router-dom";
import "../../src/index.css";
const MobileLogIn = () => {
  const dispatch = useDispatch();
  const { initSession, isLoading, error } = useSelector((state) => state.init);
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
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);

  // Extract the redirect_url parameter from the query parameters
  const redirectUrl = queryParams.get("redirect_url");

  const handleLoadingPage = async (e) => {
    const userData = {
      mainparams,
      redirectUrl,
    };

    try {
      const response = await dispatch(initSessionID(userData));
      const message = response?.payload?.msg;
      const URL = response?.payload?.url;

      if (message === "error") {
        // Redirect to specific url
        window.location.href = `${URL}`;
      }
    } catch (error) {
      throw new Error("An error occurred while initializing session.");
    }
  };

  useEffect(() => {
    if (!initSession) {
      handleLoadingPage();
    }
  }, []);
  return (
    <div className="mainContainer">
      <>
        {isLoading ? (
          <div className="flex justify-center items-center h-screen">
            <Radio
              visible={true}
              height={90}
              width={90}
              ariaLabel="radio-loading"
              wrapperStyle={{}}
              wrapperClassName="radio-wrapper"
              color="#1ff507"
            />
          </div>
        ) : error ? (
          <Navigate to="/503" />
        ) : (
          <div className="isolate md:py-4 md:px-4">
            <div className="shadow-sm mx-auto md:mt-14 max-w-5xl px-2 py-2 md:py-6 md:px-6">
              <MyMobileTabs />
            </div>
          </div>
        )}
      </>
    </div>
  );
};

export default MobileLogIn;

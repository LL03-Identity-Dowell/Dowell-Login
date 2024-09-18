import { useLocation } from "react-router-dom";
import { useSelector } from "react-redux";

import Coordinate from "./Coordinate";
import { detectBrowser } from "./browserUtils";
import { getDeviceType, getOperatingSystem } from "./deviceUtils";

export const CommonData = () => {
  // Get the random session ID from the Redux store
  const { initSession } = useSelector((state) => state.init);
  const randomSession = initSession ? initSession.random_session : "";

  const time = new Date().toLocaleTimeString();
  const os = getOperatingSystem();
  const device = getDeviceType();
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const browser = detectBrowser();
  const location = Coordinate();

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
  const language = navigator.language;

  return {
    time,
    ip: "",
    os,
    device,
    location,
    timezone,
    language,
    browser,
    mainparams,
    randomSession,
    redirectUrl,
  };
};

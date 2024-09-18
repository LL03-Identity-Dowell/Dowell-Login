import useLocationEnabled from "../utils/useLocationEnabled";
import { useState, useEffect } from "react";
import { getOperatingSystem, getDeviceType } from "../utils/deviceUtils";
import { detectBrowser } from "../utils/browserUtils";
import axios from "axios";
import { linkLogin } from "../redux/loginSlice";
import { useDispatch, useSelector } from "react-redux";
const LinkLogin = () => {
  const dispatch = useDispatch();
  const isLocationEnabled = useLocationEnabled();
  const [isFirefox, setIsFireFox] = useState(false);
  const [latitude, setLatitude] = useState("");
  const [longitude, setLongitude] = useState("");
  const [time, setTime] = useState("");
  const [os, setOs] = useState("");
  const [device, setDevice] = useState("");
  const [timezone, setTimezone] = useState("");
  const [browser, setBrowser] = useState("");
  const [ip, setIp] = useState("");
  const { userInfo, error } = useSelector((state) => state.login);

  const handleSubmit = () => {
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
    const location = `${latitude} ${longitude}`;
    const userData = {
      location,
      time,
      os,
      device,
      timezone,
      browser,
      ip,
      data: mainparams,
      language: "en",
    };
    dispatch(linkLogin(userData));
  };

  const fetchIP = async () => {
    const response = await axios.get("https://api.ipify.org?format=json");
    setIp(response.data.ip);
  };
  const getDetail = () => {
    const OS = getOperatingSystem();
    const Device = getDeviceType();
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const Browser = detectBrowser();
    const Time = new Date().toLocaleTimeString();

    setDevice(Device);
    setOs(OS);
    setTimezone(timeZone);
    setBrowser(Browser);
    setTime(Time);
    fetchIP();
  };

  const getLocation = (position) => {
    setLatitude(position.latitude);
    setLongitude(position.longitude);
    getDetail();
  };

  const askLocation = () => {
    navigator.geolocation.getCurrentPosition((position) =>
      getLocation(position.coords)
    );
  };

  const checkBrowser = () => {
    let userBrowser = navigator.userAgent;
    if (userBrowser.includes("Firefox")) {
      setIsFireFox(true);
    } else {
      setIsFireFox(false);
    }
  };
  useEffect(() => {
    if (userInfo) {
      window.location.href = userInfo.url;
    }
  }, [userInfo]);
  useEffect(() => {
    if (
      latitude &&
      longitude &&
      time &&
      os &&
      device &&
      timezone &&
      browser &&
      ip
    ) {
      handleSubmit();
    }
  }, [latitude, longitude, time, os, device, timezone, browser, ip]);

  useEffect(() => {
    checkBrowser();
    askLocation();
  }, []);

  return (
    <div className="mainContainer">
      {!isLocationEnabled ? (
        <div className="locationBanner">
          <h1 className="locationText">Click allow location to proceed.</h1>
          {isFirefox && (
            <>
              <p className="smallText">
                Please check the "
                <span className="boldText">Remember this decision</span>" box on
                Firefox
              </p>
              <div className="fireFoxBox smallText">
                {" "}
                <input
                  type="checkbox"
                  checked={true}
                  className="firefoxCheckbox"
                />{" "}
                Remember this decision{" "}
              </div>{" "}
            </>
          )}
        </div>
      ) : error ? (
        <h1 className="errorMessage">
          An Error has occurred. Please try again.
        </h1>
      ) : (
        <div class="box"></div>
      )}
    </div>
  );
};

export default LinkLogin;

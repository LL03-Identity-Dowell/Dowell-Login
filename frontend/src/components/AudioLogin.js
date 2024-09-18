import React, { useState, useEffect } from "react";
import { FaFileUpload } from "react-icons/fa";
import { ReactMic } from "react-mic";
import AudioPlayer from "../utils/AudioPlayer";
import { getOperatingSystem, getDeviceType } from "../utils/deviceUtils";
import { detectBrowser } from "../utils/browserUtils";
import axios from "axios";
import { toast } from "react-toastify";
import { voiceLogin } from "../redux/loginSlice";
import { useDispatch, useSelector } from "react-redux";
import { useLocation } from "react-router-dom";
import "../../src/index.css";

const AudioLogin = () => {
  const dispatch = useDispatch();
  const [isRecording, setIsRecording] = useState(false);
  const [voiceData, setVoiceData] = useState("");
  const [latitude, setLatitude] = useState("");
  const [longitude, setLongitude] = useState("");
  const [time, setTime] = useState("");
  const [os, setOs] = useState("");
  const [device, setDevice] = useState("");
  const [timezone, setTimezone] = useState("");
  const [browser, setBrowser] = useState("");
  const [ip, setIp] = useState("");
  const [start, setStart] = useState(false);
  const [clock, setClock] = useState(120);
  const { initSession } = useSelector((state) => state.init);
  const randomSession = initSession.random_session;
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

  const handleSubmit = () => {
    setStart(true);
    setClock(120);
    const userData = {
      time,
      timezone,
      os,
      device,
      browser,
      ip,
      location: `${latitude} ${longitude}`,
      voiceData,
      language: "en",
      randomSession,
      redirectUrl,
      data: mainparams,
    };
    console.log("User Data", userData);
    dispatch(voiceLogin(userData));
    setVoiceData("");
  };
  const handleAudioUpload = (audioData) => {
    setVoiceData(audioData);
    setIsRecording(false);
    toast.success("Audio recorded");
  };

  const handleStartRecording = () => {
    setVoiceData("");
    setTimeout(() => {
      setIsRecording(true);
    }, 10);
  };

  const handleStopRecording = () => {
    setIsRecording(false);
  };
  const fetchIP = async () => {
    const response = await axios.get("https://api.ipify.org?format=json");
    setIp(response.data.ip);
  };

  const getLocation = (position) => {
    setLatitude(position.latitude);
    setLongitude(position.longitude);
  };
  const askLocation = () => {
    navigator.geolocation.getCurrentPosition((position) =>
      getLocation(position.coords)
    );
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
  useEffect(() => {
    let timerId;
    if (start && clock > 0) {
      timerId = setTimeout(() => setClock(clock - 1), 1000);
    } else if (clock === 0) {
      setStart(false); // Stop the countdown when time reaches zero
    }
    return () => clearTimeout(timerId);
  }, [clock, start]);
  const minutes = Math.floor(clock / 60);
  const seconds = clock % 60;
  useEffect(() => {
    getDetail();
    askLocation();
  }, []);
  return (
    <div className="flex flex-col justify-center items-center space-y-4 mx-auto">
      <div className="w-full max-w-md p-4 border border-dashed border-gray-300 rounded-lg bg-gray-50 flex flex-col items-center justify-center ">
        {voiceData ? (
          <AudioPlayer url={voiceData.blobURL} />
        ) : (
          !voiceData && (
            <ReactMic
              record={isRecording}
              className={"mediaplayer"}
              onStop={(audioData) => {
                handleAudioUpload(audioData);
              }}
            />
          )
        )}

        <button
          onClick={isRecording ? handleStopRecording : handleStartRecording}
          type="button"
          className={`${
            isRecording ? "bg-red-500" : "bg-green-500"
          } flex items-center justify-center h-10 px-6 font-semibold rounded-md border hover:bg-green-700 text-white `}
        >
          {isRecording ? "Stop Recording" : "Start Recording"}
        </button>
      </div>

      <button
        type="button"
        className="flex items-center justify-center h-10 px-6 font-semibold rounded-md border bg-green-500 hover:bg-green-700 text-white"
        onClick={() => {
          handleSubmit();
        }}
        disabled={start || !voiceData}
      >
        <FaFileUpload className="mr-2" />
        Upload
      </button>
      {start && (
        <h1 className="timerText">
          Retry after : {minutes.toString().padStart(2, "0")}:
          {seconds.toString().padStart(2, "0")}
        </h1>
      )}
    </div>
  );
};

export default AudioLogin;

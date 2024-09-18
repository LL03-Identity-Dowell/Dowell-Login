import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { MdAddAPhoto, MdLogin } from "react-icons/md";
import { AiFillAudio } from "react-icons/ai";
import useLocationEnabled from "../utils/useLocationEnabled";
import DoWellVerticalLogo from "../assets/images/Dowell-logo-Vertical.jpeg";
import FaceLogin from "../components/FaceLogin";
import AudioLogin from "../components/AudioLogin";

const MediaLogin = () => {
  const [activeComponent, setActiveComponent] = useState(null);
  const [activeButton, setActiveButton] = useState(null);
  const navigate = useNavigate();
  const [isFirefox, setIsFireFox] = useState(false);
  const isLocationEnabled = useLocationEnabled();
  const handleComponentChange = (component, buttonName) => {
    setActiveComponent(component);
    setActiveButton(buttonName);
  };

  useEffect(() => {
    let userBrowser = navigator.userAgent;
    if (userBrowser.includes("Firefox")) {
      setIsFireFox(true);
    } else {
      setIsFireFox(false);
    }
  }, []);
  const askLocation = () => {
    navigator.geolocation.getCurrentPosition(
      (position) =>
        //console.log(position)
        position
    );
  };

  useEffect(() => {
    askLocation();
  }, []);
  return (
    <>
      {!isLocationEnabled ? (
        <div className="mainContainer">
          <div className="locationBanner">
            <h1 className="locationText">Click allow location to proceed.</h1>
            {isFirefox && (
              <>
                <p className="smallText">
                  Please check the "
                  <span className="boldText">Remember this decision</span>" box
                  on Firefox
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
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center h-screen bg-gray-50 mx-auto mt-0">
          <div className="max-w-screen-lg bg-white rounded-xl shadow-md overflow-hidden mb-6">
            <div className="p-8 text-center">
              <img
                className="h-28 w-28 mx-auto object-cover rounded-full mb-4"
                src={DoWellVerticalLogo}
                alt="Dowell logo"
                loading="lazy"
              />
              <h1 className="uppercase tracking-wide text-sm text-gray-900 font-semibold mb-6">
                Log-in using different ways
              </h1>

              <div className="flex flex-col md:flex-row space-y-2 md:space-y-0 md:space-x-4">
                <button
                  className={`flex items-center justify-center h-10 px-6 font-semibold rounded-md border md:mb-0 ${
                    activeButton === "camera" ? "bg-green-900" : "bg-green-500"
                  } hover:bg-green-600 text-white`}
                  type="submit"
                  onClick={() => handleComponentChange(<FaceLogin />, "camera")}
                >
                  <MdAddAPhoto className="mr-2" />
                  Take Photo
                </button>

                <button
                  className={`flex items-center justify-center h-10 px-6 font-semibold rounded-md border mb-2 md:mb-0 ${
                    activeButton === "upload" ? "bg-green-900" : "bg-green-500"
                  } hover:bg-green-600 text-white`}
                  type="button"
                  onClick={() => handleComponentChange(<AudioLogin />, "audio")}
                >
                  <AiFillAudio className="mr-2" />
                  Record Voice
                </button>

                <button
                  className={`flex items-center justify-center h-10 px-6 font-semibold rounded-md border ${
                    activeButton === "login" ? "bg-green-900" : "bg-green-500"
                  } hover:bg-green-600 text-white`}
                  type="button"
                  onClick={() => navigate("/")}
                  disabled={!activeComponent}
                >
                  <MdLogin className="mr-2" />
                  Login
                </button>
              </div>
            </div>
          </div>

          <div className="mx-auto">{activeComponent}</div>
        </div>
      )}
    </>
  );
};

export default MediaLogin;

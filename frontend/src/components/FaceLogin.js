import React, { useCallback, useEffect, useRef, useState } from "react";
import Webcam from "react-webcam";
import { useDispatch, useSelector } from "react-redux";
import { toast } from "react-toastify";
import { MdAddAPhoto } from "react-icons/md";
import { FaCamera, FaFileUpload } from "react-icons/fa";
import { CommonData } from "../utils/commonUtils";
import { uploadPhoto } from "../redux/faceLoginSlice";
import "../../src/index.css";
import * as faceapi from "face-api.js";

const FaceLogin = () => {
  const {
    time,
    ip,
    os,
    device,
    location,
    timezone,
    language,
    browser,
    mainparams,
    randomSession,
    redirectUrl,
  } = CommonData();

  // Add reference to the webcam
  // access the webcam instance and take a screenshot
  const webcamRef = useRef(null);
  const [imgSrc, setImgSrc] = useState(null);
  const [clock, setClock] = useState(120);
  const [start, setStart] = useState(false);
  const [faceDetected, setFaceDetected] = useState(false);
  const dispatch = useDispatch();
  const { error, upload, picLoading } = useSelector((state) => state.faceLogin);

  // Get the loading state for initSessionID
  const { isLoading } = useSelector((state) => state.init);
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
  // create a capture function
  const handleCapture = useCallback(async () => {
    const imageSrc = webcamRef.current.getScreenshot();
    const img = new Image();
    img.src = imageSrc;
    await img.decode(); // Wait for the image to load
    const detections = await faceapi
      .detectAllFaces(img, new faceapi.TinyFaceDetectorOptions())
      .withFaceLandmarks()
      .withFaceExpressions();
    setFaceDetected(detections.length ? true : false);
    setImgSrc(imageSrc);
    if (!detections.length) {
      toast.error("Face not detected");
    }
  }, [webcamRef, setImgSrc]);

  const handleRetake = () => {
    setImgSrc(null);
  };

  const handleUpload = async () => {
    console.log("Is face detected", faceDetected);
    // Check if imageSrc is not null
    setStart(true);
    setClock(120);
    if (!imgSrc) {
      toast.error("No image to upload.");
      return;
    }

    try {
      // Additional data
      const additionalData = {
        time,
        ip,
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
      const formData = {
        imgSrc,
        additionalData,
      };

      // Dispatch the action with both formData and additional data
      dispatch(uploadPhoto(formData));
    } catch (error) {
      // Handle error
      console.error("Error uploading photo:", error);
    }
  };

  //  Use useEffect to show success and error messages using react-toastify
  useEffect(() => {
    const showToast = (message, isSuccess = false) => {
      if (message && !picLoading) {
        isSuccess ? toast.success(message) : toast.error(message);
      }
    };

    showToast(upload, true);
    showToast(error);
  }, [error, upload, picLoading]);
  useEffect(() => {
    const loadModels = async () => {
      console.log("This is step 1");
      await faceapi.nets.tinyFaceDetector.loadFromUri("/models");
      console.log("This is step 2");
      await faceapi.nets.faceLandmark68Net.loadFromUri("/models");
      console.log("This is step 3");
      await faceapi.nets.faceRecognitionNet.loadFromUri("/models");
      console.log("This is step 4");
      await faceapi.nets.faceExpressionNet.loadFromUri("/models");
      console.log("I look like all are loaded");
    };

    loadModels();
  }, []);
  // Render loading state while initializing session ID
  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="flex justify-center items-center relative">
      <div className="bg-gray-200 rounded-xl p-2">
        {imgSrc ? (
          <div className="mt-4 space-y-2">
            <img
              src={imgSrc}
              alt="CapturedPhoto"
              className="w-full h-auto rounded-md shadow-md"
            />
            <div className="text-center md:text-left space-y-6">
              <div className="flex space-x-3 items-center justify-center">
                <button
                  type="button"
                  className="flex items-center justify-center h-10 px-6 font-semibold rounded-md border bg-green-500 hover:bg-green-700 text-white"
                  onClick={handleRetake}
                >
                  <MdAddAPhoto className="mr-2" />
                  Retake
                </button>

                <button
                  type="button"
                  className="flex items-center justify-center h-10 px-6 font-semibold rounded-md border bg-green-500 hover:bg-green-700 text-white"
                  onClick={handleUpload}
                  disabled={start || !faceDetected}
                >
                  <FaFileUpload className="mr-2" />
                  Upload
                </button>
              </div>
              {start && (
                <h1 className="timerText">
                  Retry after : {minutes.toString().padStart(2, "0")}:
                  {seconds.toString().padStart(2, "0")}
                </h1>
              )}
            </div>
          </div>
        ) : (
          <>
            <div className="cameraContainer">
              <Webcam
                audio={false}
                ref={webcamRef}
                screenshotFormat="image/jpeg"
                width={320}
                height={240}
                className="mb-2 rounded-md"
              />
              <div className="ovalContainer" />
            </div>

            <button
              type="button"
              className="flex items-center justify-center w-full h-10 px-4 font-semibold rounded-md border bg-green-500 hover:bg-green-700 text-white"
              onClick={handleCapture}
            >
              <FaCamera className="mr-2" />
              Capture
            </button>
          </>
        )}
      </div>
    </div>
  );
};

export default FaceLogin;

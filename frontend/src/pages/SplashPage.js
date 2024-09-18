import React from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import DoWellVerticalLogo from "../assets/images/Dowell-logo-Vertical.jpeg";

const SplashPage = () => {
  const navigate = useNavigate();
  const { username } = useParams();
  // Use the useLocation hook to access the URL parameters passed from the login page
  const location = useLocation();
  const mainparams = location.search.substring(1); // Remove the leading '?' character

  return (
    <div className="antialiased bg-gray-100 flex items-center justify-center h-screen">
      <div className="md:flex rounded-xl p-8 md:p-0 dark:bg-slate-800 space-y-6 space-x-2 md:space-x-6 text-gray-500 bg-gray-50 drop-shadow-lg ">
        <img
          src={DoWellVerticalLogo}
          alt="DoWell logo"
          className="w-24 h-24 md:w-48 md:h-auto md:rounded-none rounded-full mx-auto drop-shadow-sm"
        />
        <div className="pt-6 md:p-8 text-center md:text-left space-y-4">
          <h1 className="font-bold text-xl text-slate-900 truncate text-center">
            Welcome to UXLiving Lab!
          </h1>
          <p className="text-gray-600 mb-4 text-center">
            User{" "}
            <strong className="underline text-green-500">{username}</strong>{" "}
            successfully registered!
          </p>
          <div className="flex flex-row items-center justify-center mt-20">
            <button
              className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-xl drop-shadow-xl mr-4"
              onClick={() => navigate(`/?${mainparams}`)}
            >
              Login
            </button>
            <button
              className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-xl drop-shadow-xl"
              onClick={() => navigate("/register")}
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SplashPage;

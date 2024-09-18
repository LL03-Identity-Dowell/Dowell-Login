import React, { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { Radio } from "react-loader-spinner";
import { toast } from "react-toastify";
import { logoutUser } from "../redux/logoutSlice";
import DoWellVerticalLogo from "../assets/images/Dowell-logo-Vertical.jpeg";
import QR_Code from "../assets/images/QR-Code.png";
import Samanta from "../assets/images/samanta.webp";

const SignOutPage = () => {
  const [clicked, setClicked] = useState(false);

  const dispatch = useDispatch();
  const navigate = useNavigate();

  const { loading, error, loggedOut } =
    useSelector((state) => state.logout) || {};

  const handleSignOut = () => {
    dispatch(logoutUser({ session_id: "s20vytmoshxrt6ma0m5rzc59vp35ikv0" }));
  };

  // Use the useLocation hook to access the URL parameters
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);

  // Extract the redirect_url parameter from the query parameters
  const redirectUrl = queryParams.get("redirect_url");

  // Extract the returnurl parameter from the query parameters
  const returnUrl = queryParams.get("returnurl");

  // Handle cancel
  const handleCancel = () => {
    if (returnUrl) {
      window.location.href = returnUrl;
    } else {
      navigate(-1);
    }
  };

  // Display the loggedOut and error messages
  useEffect(() => {
    if (loggedOut) {
      toast.success(loggedOut);
    } else {
      toast.error(error);
    }
  }, [loggedOut, error]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="max-w-3xl w-full p-6 space-y-6 bg-white rounded-lg shadow-lg">
        <div className="flex items-center justify-center">
          <img
            src={DoWellVerticalLogo}
            alt="DoWell logo"
            className="h-28 w-28 md:h-36 md:w-36 rounded-xl drop-shadow-xl"
          />
        </div>

        <div className="rounded-xl text-gray-500 bg-gray-50 drop-shadow-lg border border-green-300">
          <div className="flex flex-col md:flex-row mx-auto md:space-x-4 space-x-4 space-y-2 p-2 items-center justify-center">
            <div className="bg-green-200 p-4 rounded-lg w-full md:w-96">
              <h3 className="font-base text-slate-900 leading-normal text-justify">
                Scan QR Code to contribute your comments and suggestions about
                this application in two minutes and get rewarded!
              </h3>
            </div>

            <div className="flex flex-row space-x-2">
              <div className="">
                <img
                  src={QR_Code}
                  alt="QR_Code"
                  className="h-28 w-28 md:h-36 md:w-36 rounded-xl drop-shadow-xl"
                  loading="lazy"
                />
              </div>

              <div className="">
                <img
                  src={Samanta}
                  alt="Samanta"
                  className="h-24 w-24 md:h-32 md:w-32 rounded-xl drop-shadow-xl"
                  loading="lazy"
                />
                <p className="font-normal text-base text-slate-900 text-center">
                  Samanta
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-xl py-6 text-gray-500 bg-gray-50 drop-shadow-lg overflow-hidden border border-green-300">
          {!loggedOut && (
            <p className="text-gray-600 mb-4 text-center">
              Thank you, Do you want to exit?
            </p>
          )}
          <div className="flex flex-row items-center justify-center">
            {loggedOut ? (
              <div className="text-center">
                <div className="w-72 mx-auto flex items-center justify-center rounded-md bg-green-300 space-x-2 px-3.5 py-2.5 mt-8 text-white shadow-sm hover:bg-green-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-700">
                  <Link
                    to={redirectUrl ? `/?redirect_url=${redirectUrl}` : "/"}
                  >
                    Log in
                  </Link>
                </div>
              </div>
            ) : (
              <>
                <button
                  className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-xl drop-shadow-xl mr-4"
                  onClick={handleSignOut}
                  disabled={loading}
                >
                  {loading ? (
                    <Radio
                      visible={true}
                      height={30}
                      width={30}
                      ariaLabel="radio-loading"
                      wrapperStyle={{}}
                      wrapperClassName="radio-wrapper"
                      color="#1ff507"
                    />
                  ) : (
                    "Yes"
                  )}
                </button>
                <button
                  className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-xl drop-shadow-xl"
                  onClick={handleCancel}
                  disabled={loading}
                >
                  {loading ? (
                    <Radio
                      visible={true}
                      height={30}
                      width={30}
                      ariaLabel="radio-loading"
                      wrapperStyle={{}}
                      wrapperClassName="radio-wrapper"
                      color="#1ff507"
                    />
                  ) : (
                    "No"
                  )}
                </button>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-col py-6 rounded-xl text-gray-500 bg-gray-50 drop-shadow-lg overflow-hidden border border-green-300">
          <p className="text-gray-600 mb-4 text-center">
            Do you wish to recommend this application to your friend?
          </p>
          <div className="flex flex-row items-center justify-center space-x-2">
            <p className={clicked ? "text-center bg-green" : ""}>
              {clicked ? "Thank you for your response!" : ""}
            </p>
            {!clicked && (
              <>
                <button
                  value="Yes"
                  type="button"
                  onClick={() => setClicked(true)}
                  className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-xl drop-shadow-xl"
                >
                  Yes
                </button>

                <button
                  value="Maybe"
                  type="button"
                  onClick={() => setClicked(true)}
                  className="bg-yellow-500 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded-xl drop-shadow-xl"
                >
                  Maybe
                </button>

                <button
                  value="No"
                  type="button"
                  onClick={() => setClicked(true)}
                  className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-xl drop-shadow-xl"
                >
                  No
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SignOutPage;

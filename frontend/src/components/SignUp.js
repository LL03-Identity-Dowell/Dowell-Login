import React, { useEffect, useState } from "react";
import { MdAddAPhoto, MdInfo } from "react-icons/md";
import DoWellVerticalLogo from "../assets/images/Dowell-logo-Vertical.jpeg";
import WorkFlowLogo from "../assets/product logo/Workflow-AI-2.png"
import LivingLabAdmin from "../assets/product logo/Living-Lab-Admin-1.png"
import CustomerSupportLogo from "../assets/product logo/customer-support-centre.png" 
import ApiLogo from "../assets/product logo/API.svg" 
import DowellMapsLogo from "../assets/product logo/dowell-maps-1.png" 
import DatacubeLogo from "../assets/product logo/datacube-f09edb53.svg" 
import LegalzardLogo from "../assets/product logo/Legalzard-1.png" 
import LivingLabChatLogo from "../assets/product logo/Livinglab-chat-1.png" 
import LogoScanLogo from "../assets/product logo/Logo-Scan-1.png" 
import PermutationCalculatorLogo from "../assets/product logo/Permutation-calculator.png" 
import SalesAgentAppLogo from "../assets/product logo/Sales-agent-app.png" 
import SecureDataLogo from "../assets/product logo/secure-data.png" 
import SecureRepoLogo from "../assets/product logo/secure-repositories.png" 
import SocialMediaLogo from "../assets/product logo/Social-media-automation-1.png" 
import TeamManagementLogo from "../assets/product logo/Social-media-automation-2.png" 

import { Link, useLocation } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { fetchCountries } from "../redux/countriesSlice";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import * as yup from "yup";
import { Radio } from "react-loader-spinner";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import {
  registerUser,
  sendEmailOTP,
  sendMobileOTP,
} from "../redux/registrationSlice";
import PasswordInput from "./passwordInput";
import useTimedMessage from "./useTimedMessage";
import {
  resetUsernameAvailability,
  resetUsernameError,
  validateUsernameAsync,
} from "../redux/validateUsernameSlice";
import { MdClose } from "react-icons/md";

// Schema for validation inputs
const schema = yup.object().shape({
  Firstname: yup
    .string()
    .required("First Name is required")
    .max(20)
    .matches(/^[A-Za-z]+$/, {
      message: "Last Name must not include numbers",
    }),
  Lastname: yup
    .string()
    .required("Last Name is required")
    .max(20)
    .matches(/^[A-Za-z]+$/, { message: "Last Name must not include numbers" }),
  Username: yup
    .string()
    .required("User Name is required")
    .max(20)
    .matches(/^\S*$/, "Username must not contain spaces")
    .matches(/^[A-Za-z0-9]+$/, "Username must not include special characters")
    .notOneOf(
      ["administrator", "uxlivinglab", "dowellresearch", "dowellteam", "admin"],
      "Username not allowed"
    ),
  user_type: yup.string().required("User Type is required"),
  Password: yup
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(99)
    .required("Password is required"),
  confirm_password: yup
    .string()
    .oneOf([yup.ref("Password")], "Passwords must match")
    .required("Confirm Password is required"),
  Email: yup
    .string()
    .email("Invalid Email format")
    .required("Email is required"),
  otp: yup
    .string()
    .required("OTP is required")
    .matches(/^[0-9]+$/, "OTP must contain only numbers"),
  user_country: yup.string().required("Country is required"),
  phonecode: yup
    .string()
    .required("Country Code is required")
    .matches(/^\d{1,3}$/, "Country Code must be 1 to 3 digits"),
  Phone: yup
    .string()
    .required("Phone number is required")
    .matches(/^\d{9,15}$/, "Phone number must have 9 to 15 digits"),
  sms: yup.string().matches(/^[0-9]+$/, "SMS must contain only numbers"),
  Profile_Image: yup
    .mixed()
    .test("fileFormat", "Unsupported file format", (value) => {
      if (!value || !value[0]) return true; // Allow empty value
      return (
        value[0].type === "image/jpeg" ||
        value[0].type === "image/png" ||
        value[0].type === "image/gif"
      );
    })
    .test("fileSize", "File size is too large", (value) => {
      if (!value || !value[0]) return true; // Allow empty value
      return value[0].size <= 1024 * 1024;
    }),
  policy_status: yup
    .boolean()
    .required("Please accept the Terms & Conditions")
    .oneOf([true], "Please accept the Terms & Conditions")
    .default(false),
  newsletter: yup
    .boolean()
    .oneOf([true], "Accept Newsletter Terms & Conditions")
    .default(false),
});

const SignUp = () => {
  const [attemptsOtp, setAttemptsOtp] = useState(2);
  const [attemptsSms, setAttemptsSms] = useState(2);
  const [otpCountdown, setOtpCountdown] = useState(0);
  const [smsCountdown, setSmsCountdown] = useState(0);
  const [timerText, setTimerText] = useState("");
  const [exempted, setExempted] = useState(false);
  const [lastClickedButton, setLastClickedButton] = useState(null);
  const [usernameMessages, setUsernameMessages] = useTimedMessage();
  const [policyDisplay, setPolicyDispaly] = useState(false);
  const [signUpImage, setSignUpImage] = useState(null);
  const [showCloseIcon, setShowCloseIcon] = useState(false);
  const [iframeLoading, setIframeLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");
  const [emailErrorMessage, setEmailErrorMessage] = useState(null);
  // Use the custom hook to handle the verification
  const [verificationRequested, setVerificationRequested] = useState(false);

  const dispatch = useDispatch();
  const countries = useSelector((state) => state.countries);
  const {
    otpLoading,
    smsLoading,
    regLoading,
    error,
    registered,
    otpSent,
    smsSent,
  } = useSelector((state) => state.registration) || {};
  const { isError, isUsernameAvailable } =
    useSelector((state) => state.validateUsername) || {};

  const conditionalSchema = !exempted
    ? schema
    : yup.object().shape({
        sms: yup.string().nullable(),
      });

  const {
    handleSubmit,
    register,
    formState: { errors },
    watch,
    setValue,
    getValues,
    reset,
  } = useForm({
    resolver: yupResolver(conditionalSchema),
  });

  // a hook to redirect the user to the signin page
  const navigate = useNavigate();

  // Use the useLocation hook to access the URL parameters passed from the login page
  const location = useLocation();
  const mainParams = location.search.substring(1); // Remove the leading '?' character

  // dispatch countries list
  useEffect(() => {
    dispatch(fetchCountries());
  }, [dispatch]);

  // dispatch email otp
  const handleEmailOTP = () => {
    if (attemptsOtp > 0) {
      const {
        Firstname,
        Lastname,
        Username,
        user_type,
        Email,
        Password,
        confirm_password,
      } = watch();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      const valideEmail = emailRegex.test(Email);
      if (!valideEmail) {
        setEmailErrorMessage("Invaid email format!");
        return;
      } else {
        setEmailErrorMessage(null);
      }
      if (
        Firstname &&
        Lastname &&
        Username &&
        user_type &&
        Email &&
        Password &&
        confirm_password
      ) {
        setAttemptsOtp((prevAttempts) => prevAttempts - 1);
      }
      const email = watch("Email");
      const username = watch("Username");
      if (email && username) {
        dispatch(sendEmailOTP({ email, username, usage: "create_account" }));
        setOtpCountdown(60); // Reset the OTP countdown timer to 60 seconds
        setVerificationRequested(true);
        setLastClickedButton("otp");
      }
    }
  };

  // Countdown timer for OTP
  useEffect(() => {
    if (otpCountdown > 0) {
      const otpTimer = setTimeout(() => {
        setOtpCountdown((prevCountdown) => prevCountdown - 1);
      }, 1000); // 1 second
      return () => clearTimeout(otpTimer);
    }
  }, [otpCountdown]);
  const handlePolicyDisplay = () => {
    setPolicyDispaly(!policyDisplay);
  };
  // Dispatch mobile sms
  const handleMobileOTP = (data) => {
    const { phonecode, Phone } = data;
    if (attemptsSms > 0 && !exempted && smsCountdown === 0) {
      const {
        Firstname,
        Lastname,
        Username,
        user_type,
        Email,
        Password,
        confirm_password,
        user_country,
        otp,
      } = watch();
      if (
        Firstname &&
        Lastname &&
        Username &&
        user_type &&
        Email &&
        Password &&
        confirm_password &&
        user_country &&
        otp &&
        phonecode &&
        Phone
      ) {
        setAttemptsSms((prevAttempts) => prevAttempts - 1);
      }
      if (phonecode && Phone && Phone.length > 0) {
        dispatch(sendMobileOTP({ phonecode, Phone }));
        setSmsCountdown(attemptsSms === 1 ? 15 : 60); // Reset the SMS countdown timer to 60 seconds
        setTimerText(
          attemptsSms === 1 ? "Exempt option in: " : "Resend SMS in: "
        ); // Reset the SMS countdown timer to 60 seconds
        setVerificationRequested(true);
        setLastClickedButton("sms");
      }
    } else {
      setExempted(true);
    }
  };

  // Countdown timer for SMS
  useEffect(() => {
    if (smsCountdown > 0) {
      const smsTimer = setTimeout(() => {
        setSmsCountdown((prevCountdown) => prevCountdown - 1);
      }, 1000); // 1 second
      return () => clearTimeout(smsTimer);
    }
  }, [smsCountdown]);

  // dispatch registered user
  const registeredUserInfo = () => {
    if (verificationRequested) {
      const {
        Firstname,
        Lastname,
        Username,
        user_type,
        Email,
        Password,
        confirm_password,
        user_country,
        phonecode,
        Phone,
        otp,
        Profile_Image,
        policy_status,
        newsletter,
      } = watch();

      // Determine the value of sms based on the exempted checkbox
      const smsValue = exempted ? null : getValues("sms");
      const time = new Date();
      let formData = new FormData();
      formData.append("Profile_Image", Profile_Image);
      formData.append("Firstname", Firstname);
      formData.append("Lastname", Lastname);
      formData.append("Username", Username);
      formData.append("user_type", user_type);
      formData.append("Email", Email);
      formData.append("Password", Password);
      formData.append("confirm_password", confirm_password);
      formData.append("user_country", user_country);
      formData.append("phonecode", phonecode);
      formData.append("Phone", Phone);
      formData.append("otp", otp);
      formData.append("sms", smsValue);
      formData.append("policy_status", policy_status);
      formData.append("newsletter", newsletter);
      formData.append("time", time);

      // Dispatch the registerUser action with the form data
      dispatch(registerUser(formData));
    } else {
      throw new Error(error.response.data.info);
    }
  };

  // Redirect when `registered` changes
  useEffect(() => {
    if (registered) {
      const username = getValues("Username");
      setTimeout(() => {
        navigate(`/splash/${username}${mainParams ? `?${mainParams}` : ""}`);
      }, 1000);
    }
  }, [getValues, registered, navigate, mainParams]);

  // Check a username availability
  const checkUsernameAvailability = async () => {
    const username = watch("Username");
    var regex = /^[a-zA-Z0-9]+$/;
    const letterRegex = /^[a-zA-Z]/;
    const validNamestartWithAlphabet = letterRegex.test(username);
    const validUserName = regex.test(username);
    if (!validUserName && username) {
      setErrorMessage("Username must not contain spaces or special characters");
      reset({ Username: "" });
      return;
    } else if (!validNamestartWithAlphabet) {
      setErrorMessage("Username must start with an alphabet");
      reset({ Username: "" });
      return;
    } else {
      setErrorMessage("");
    }
    if (username) {
      await dispatch(validateUsernameAsync(username));
    }
  };
  useEffect(() => {
    if (isUsernameAvailable) {
      // Do not reset the form if the username is not available
      setUsernameMessages(isUsernameAvailable, "success", 5000);
      dispatch(resetUsernameAvailability());
    }

    if (isError) {
      setUsernameMessages(isError, "error", 5000);
      // Reset only the username field
      dispatch(resetUsernameError());
      reset({ Username: "" });
    }
  }, [isUsernameAvailable, isError, reset]);

  //  Use useEffect to show success and error messages using react-toastify
  useEffect(() => {
    const showToast = (message, isSuccess = false) => {
      if (message && !otpLoading && !smsLoading && !regLoading) {
        isSuccess ? toast.success(message) : toast.error(message);
      }
    };

    // Show toasts only if registered is false
    if (!registered) {
      if (otpSent && lastClickedButton === "otp") {
        showToast(otpSent, true);
      }
      if (smsSent && lastClickedButton === "sms") {
        showToast(smsSent, true);
      }
    }
    showToast(registered, true);
    showToast(error);
  }, [
    otpSent,
    smsSent,
    registered,
    error,
    reset,
    otpLoading,
    smsLoading,
    regLoading,
    lastClickedButton,
  ]);
  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        setSignUpImage(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };
  

  // logo 
  const queryParams = new URLSearchParams(window.location.search);
  const redirectUrl = queryParams.get('redirect_url');
console.log(redirectUrl)
  const [productLogo, setProductLogo] = useState('');

  useEffect(() => {
    // Parse the redirect_url to extract product information
    const productInfo = redirectUrl; // Assuming the product info is the last part of the URL
    // Logic to determine the logo based on product information
    let logoUrl = '';
    switch (productInfo) {
      case 'https://ll04-finance-dowell.github.io/workflowai.online':
        logoUrl = WorkFlowLogo;
        break;
      case 'https://100093.pythonanywhere.com/home':
        logoUrl = LivingLabAdmin;
        break;
      case 'https://ll09-legalcompliance-dowell.github.io/':
        logoUrl = LegalzardLogo;
        break;
      case 'https://100050.pythonanywhere.com/calculator':
        logoUrl = PermutationCalculatorLogo;
        break;
      case 'https://ll07-team-dowell.github.io/Jobportal':
        logoUrl = TeamManagementLogo;
        break;
      case 'https://www.socialmediaautomation.uxlivinglab.online/':
        logoUrl = SocialMediaLogo;
        break;
        case 'https://ll03-identity-dowell.github.io/100096-DowellChat/#/customer-support':
        logoUrl = CustomerSupportLogo;
        break;
      case 'https://ll03-identity-dowell.github.io/100096-DowellChat/#/living-lab-chat':
        logoUrl = LivingLabChatLogo;
        break;
      case 'https://ll05-ai-dowell.github.io/100105-DowellApiKeySystem':
        logoUrl = ApiLogo;
        break;
      case 'https://ll07-team-dowell.github.io/100045-SecureRepository':
        logoUrl = SecureDataLogo
        break;
      default:
        logoUrl = DoWellVerticalLogo;
    }
    setProductLogo(logoUrl);
  }, [redirectUrl]);
  console.log(productLogo)
  return (
    <div className="isolate px-2 py-4 sm:py-12 lg:px-8">
      <div className="shadow-sm mx-auto max-w-5xl px-2 py-6 md:px-4">
        <div className="flex items-center justify-center">
          <div className="text-center space-y-2">
           <img
              src={productLogo}
              alt="DoWell logo"
              className="h-34 w-44 rounded-sm drop-shadow-md mx-auto"
            />
            <h2 className="text-xl font-semibold tracking-wide text-green-500 md:text-2xl">
              Join as New Member
            </h2>
          </div>
        </div>
        <form
          className="mx-auto mt-8 max-w-xl sm:mt-12"
          onSubmit={handleSubmit(registeredUserInfo)}
        >
          <div className="grid grid-cols-1 gap-y-6">
            <div>
              <label htmlFor="Firstname" className="label">
                First Name <span className="text-red-500">*</span>
              </label>
              <div className="mt-2.5">
                <input
                  type="text"
                  name="Firstname"
                  id="Firstname"
                  placeholder="Your First Name"
                  autoComplete="Firstname"
                  className="input-field"
                  {...register("Firstname")}
                />
                {errors.Firstname && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.Firstname.message}
                  </p>
                )}
              </div>
            </div>

            <div>
              <label htmlFor="Lastname" className="label">
                Last Name <span className="text-red-500">*</span>
              </label>
              <div className="mt-2.5">
                <input
                  type="text"
                  name="Lastname"
                  id="Lastname"
                  placeholder="Your Last Name"
                  autoComplete="family-name"
                  className="input-field"
                  {...register("Lastname")}
                />
                {errors.Lastname && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.Lastname.message}
                  </p>
                )}
              </div>
            </div>

            <div>
              <label htmlFor="Username" className="label">
                User Name <span className="text-red-500">*</span>
              </label>
              <div className="mt-2.5">
                <input
                  type="text"
                  name="Username"
                  id="Username"
                  placeholder="Enter Your Username"
                  autoComplete="Username"
                  className="input-field"
                  {...register("Username")}
                  onBlur={checkUsernameAvailability}
                />

                {errors.Username && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.Username.message}
                  </p>
                )}
                {errorMessage && (
                  <p className="text-red-500 text-xs mt-1"> {errorMessage}</p>
                )}
                {usernameMessages.map((msg) => (
                  <p
                    key={msg.id}
                    className={`text-sm font-light ${
                      msg.type === "success" ? "text-green-500" : "text-red-500"
                    }`}
                  >
                    {msg.message}
                  </p>
                ))}
              </div>
            </div>

            <div>
              <label htmlFor="user-type" className="label">
                User Type <span className="text-red-500">*</span>
              </label>
              <div className="mt-2.5">
                <select
                  name="user-type"
                  placeholder="user-type"
                  required
                  className="input-field"
                  defaultValue="live-user"
                  {...register("user_type")}
                >
                  <option value="live-user">Live User</option>
                  <option value="beta-tester">Beta Tester</option>
                </select>
              </div>
            </div>

            <div>
              <PasswordInput
                name="Password"
                register={register}
                value={getValues("Password")}
                errors={errors}
                isConfirm={false}
                onChange={setValue}
              />
            </div>

            <div>
              <PasswordInput
                name="confirm_password"
                register={register}
                value={getValues("confirm_password")}
                errors={errors}
                isConfirm={true}
                onChange={setValue}
              />
            </div>

            <div>
              <label htmlFor="Email" className="label">
                Email <span className="text-red-500">*</span>
              </label>
              <div className="mt-2.5">
                <input
                  type="Email"
                  name="Email"
                  id="Email"
                  placeholder="Enter Your Email"
                  autoComplete="Email"
                  className="input-field"
                  {...register("Email")}
                />
                {errors.Email && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.Email.message}
                  </p>
                )}
                <p className="text-red-500 text-xs mt-1">{emailErrorMessage}</p>
              </div>

              <div className="mt-2.5">
                <div className="flex flex-row space-x-3 items-center">
                  <button
                    className="btn-send px-2 py-1 self-start"
                    onClick={() => handleEmailOTP(watch())}
                    disabled={
                      otpLoading ||
                      (otpSent && otpCountdown > 0) ||
                      attemptsOtp === 0
                    }
                  >
                    {otpLoading ? (
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
                      "Get OTP"
                    )}
                  </button>
                </div>
                {/* Display the countdown timer only after the first OTP attempt */}
                {otpSent && otpCountdown > 0 && !error && (
                  <div className="text-base font-normal text-green-600">
                    Resend OTP in: {otpCountdown}s
                  </div>
                )}
                {/* Display the email OTP attempts remaining */}
                {attemptsOtp > 0 && otpSent && !error && (
                  <div>
                    <p className="text-base font-normal text-green-600">
                      Attempts remaining: {attemptsOtp}
                    </p>
                  </div>
                )}
                {/* Display checkbox to exempt from email OTP */}
                {attemptsOtp === 0 && otpCountdown === 0 && (
                  <div className="text-sm leading-6">
                    <p className="text-red-600">
                      You have to reload the page and try again!!
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div>
              <label htmlFor="otp-Email" className="label">
                Enter OTP from Email <span className="text-red-500">*</span>
              </label>

              <div className="mt-2.5">
                <input
                  type="text"
                  name="otp"
                  id="otp"
                  placeholder="Enter OTP from Email"
                  autoComplete="otp"
                  className="input-field"
                  {...register("otp")}
                />
                {errors.otp && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.otp.message}
                  </p>
                )}
              </div>
            </div>

            <div>
              <label htmlFor="user_country" className="label">
                Country <span className="text-red-500">*</span>
              </label>

              <div className="mt-2.5">
                <select
                  name="user_country"
                  type="text"
                  placeholder="Select Your Country"
                  required
                  className="input-field"
                  {...register("user_country")}
                >
                  {countries.map((country) => (
                    <option key={country.id} value={country.name}>
                      {country.name}
                    </option>
                  ))}
                </select>
                {errors.user_country && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.user_country.message}
                  </p>
                )}
              </div>
            </div>

            <div>
              <label htmlFor="county_code" className="label">
                Country Code <span className="text-red-500">*</span>
              </label>

              <div className="mt-2.5">
                <select
                  name="phonecode"
                  type="text"
                  placeholder="countries code"
                  required
                  className="input-field"
                  {...register("phonecode")}
                >
                  {countries.map((country) => (
                    <option key={country.id} value={country.country_code}>
                      {country.name}(+{country.country_code})
                    </option>
                  ))}
                </select>
                {errors.phonecode && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.phonecode.message}
                  </p>
                )}
              </div>
            </div>

            <div>
              <label htmlFor="Phone" className="label">
                Phone Number <span className="text-red-500">*</span>
              </label>
              <div className="relative mt-2.5">
                <input
                  name="Phone"
                  type="text"
                  placeholder="Enter Your Phone Number"
                  className="input-field"
                  {...register("Phone")}
                />
                {errors.Phone && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.Phone.message}
                  </p>
                )}
              </div>
              <div className="mt-2.5">
                <div className="flex flex-row space-x-3 items-center">
                  <button
                    className="btn-send px-2 py-1 self-start"
                    onClick={() => handleMobileOTP(watch())}
                    disabled={
                      smsLoading ||
                      (smsSent && smsCountdown > 0) ||
                      (attemptsSms === 0 && !exempted)
                    }
                  >
                    {smsLoading ? (
                      <Radio
                        visible={true}
                        height={30}
                        width={30}
                        ariaLabel="radio-loading"
                        wrapperStyle={{}}
                        wrapperClassName="radio-wrapper"
                        color="#1ff507"
                      />
                    ) : attemptsSms === 2 ? (
                      "Get SMS"
                    ) : (
                      "Resend"
                    )}
                  </button>
                </div>

                {/* Display the countdown timer only after the first SMS attempt */}
                {smsSent && smsCountdown > 0 && !error && (
                  <div className="text-base font-normal text-green-600 smscontainer">
                    {timerText} {smsCountdown}s
                    <div className="smsTimerDiv">
                      <MdInfo />
                      {attemptsSms >= 0 && smsSent && !error && (
                        <div className="tooltiptext">
                          <p className="tooltipInfoText">
                            If you don't get sms in two tries, you'll get option
                            to register without it's requirement.
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {!attemptsSms && !smsCountdown && (
                  <div className="relative flex gap-x-3">
                    <div className="flex h-6 items-center">
                      <input
                        id="exempt-checkbox"
                        name="exempt-checkbox"
                        type="checkbox"
                        className="h-4 w-4 rounded border-gray-300 text-green-600 focus:ring-green-600"
                        onChange={(e) => setExempted(e.target.checked)}
                      />
                    </div>
                    <div className="text-sm leading-6">
                      <p className="text-gray-600">
                        Exempt from SMS requirement
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {!exempted && (
              <div>
                <label htmlFor="sms" className="label">
                  Enter OTP from SMS <span className="text-red-500">*</span>
                </label>

                <div className="mt-2.5">
                  <input
                    type="text"
                    name="sms"
                    id="sms"
                    placeholder="Enter OTP from SMS"
                    autoComplete="sms"
                    className="input-field"
                    {...register("sms")}
                    disabled={exempted}
                  />
                  {errors.sms && (
                    <p className="text-red-500 text-xs mt-1">
                      {errors.sms.message}
                    </p>
                  )}
                </div>
              </div>
            )}

            <div>
              <label htmlFor="Profile_Image" className="label">
                Upload Photo
              </label>
              <div className="mt-2.5">
                <div className="flex flex-row items-center space-x-3">
                  <MdAddAPhoto
                    className="h-8 w-8 text-green-500"
                    aria-hidden="true"
                  />
                  {signUpImage && (
                    <div
                      className="signUpImageHolder"
                      onMouseOver={() => {
                        setShowCloseIcon(true);
                      }}
                      onMouseOut={() => {
                        setShowCloseIcon(false);
                      }}
                    >
                      <img
                        src={signUpImage}
                        className="singUpImage"
                        alt="Profile"
                        style={{ opacity: showCloseIcon && "0.6" }}
                      />
                      {showCloseIcon && (
                        <div
                          className="signUpIconContainer"
                          onClick={() => {
                            setSignUpImage(null);
                            setShowCloseIcon(false);
                          }}
                        >
                          {" "}
                          <MdClose color="white" fontSize="14px" />{" "}
                        </div>
                      )}
                    </div>
                  )}
                  {!signUpImage && (
                    <div className="text-sm leading-6 text-gray-600">
                      <label
                        htmlFor="Profile_Image"
                        className="relative cursor-pointer rounded-md bg-white font-semibold text-green-600 focus-within:outline-none focus-within:ring-2 focus-within:ring-green-600 focus-within:ring-offset-2 hover:text-green-500"
                      >
                        <span>Click here</span>
                        <input
                          id="Profile_Image"
                          name="Profile_Image"
                          type="file"
                          className="sr-only"
                          {...register("Profile_Image")}
                          accept="image/jpeg, image/png, image/gif"
                          onChange={handleImageChange}
                        />
                      </label>
                    </div>
                  )}
                </div>
              </div>
              {errors.Profile_Image && (
                <p className="text-red-500 text-xs mt-1">
                  {errors.Profile_Image.message}
                </p>
              )}
            </div>
          </div>

          <div className="mt-4 space-y-6">
            <fieldset>
              <div className="mt-4 space-y-6">
                <div className="relative flex gap-x-3">
                  <div className="flex h-6 items-center">
                    <input
                      id="policy_status"
                      name="policy_status"
                      type="checkbox"
                      className="h-4 w-4 rounded border-gray-300 text-green-600 focus:ring-green-600"
                      {...register("policy_status")}
                    />
                  </div>
                  <div className="text-sm leading-6">
                    <p className="text-gray-600">
                      Do you accept our{" "}
                      <span
                      /*                className="policyLink"
                        onClick={() => {
                          handlePolicyDisplay();
                        }} */
                      >
                        policies
                      </span>
                      ?
                    </p>
                  </div>
                  {errors.policy_status && (
                    <p className="text-red-500 text-xs mt-1">
                      {errors.policy_status.message}
                    </p>
                  )}
                </div>

                <div className="relative flex gap-x-3">
                  <div className="flex h-6 items-center">
                    <input
                      id="newsletter"
                      name="newsletter"
                      type="checkbox"
                      className="h-4 w-4 rounded border-gray-300 text-green-600 focus:ring-green-600"
                      {...register("newsletter")}
                    />
                  </div>
                  <div className="text-sm leading-6">
                    <p className="text-gray-600">
                      Do you want to subscribe to our newsletter?
                    </p>
                  </div>
                </div>
              </div>
            </fieldset>
          </div>
          {/*           <div className={policyDisplay ? "displayed" : "notDisplayed"}>
            {iframeLoading && (
              <div className="policyFrameSpinner iframespinner">
                {" "}
                <div className="box" style={{ width: "50px", height: "50px" }}>
                  {" "}
                </div>
              </div>
            )}
            <iframe
              title="policy"
              id="for_policy"
              className="policyFrame"
              loading="lazy"
              src="https://100087.pythonanywhere.com/legalpolicies/FB1010000000167475042357408025/website-privacy-policy/policies/?redirect_url=https://100014.pythonanywhere.com/legalpolicy1?s=&amp;session_id="
              allow="fullscreen"
              width="900"
              height="200"
              onLoad={() => setIframeLoading(false)}
            ></iframe>
          </div> */}

          <div className="mt-8">
            <button type="submit" className="submit-btn" disabled={regLoading}>
              {regLoading ? (
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
                "Join as a new member"
              )}
            </button>
          </div>
          <div className="flex items-center justify-center">
            <div className="w-60 rounded-md bg-green-300 py-2.5 mt-6 text-white shadow-sm hover:bg-green-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-700 text-center">
              <Link to="/">Do have an account? Log in</Link>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default SignUp;

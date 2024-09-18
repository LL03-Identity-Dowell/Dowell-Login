import React, { useState } from "react";
import LogIn from "./LogIn";
import FaceLogin from "./FaceLogin";

const AuthContainer = () => {
  const [userData, setUserData] = useState(null);

  const handleUserInfo = (data) => {
    setUserData(data);
  };

  const handleImageUpload = (imageData) => {
    // Handle the uploaded image data if needed
    console.log("Image uploaded:", imageData);
  };

  return (
    <>
      <LogIn onUserInfo={handleUserInfo} />
      <FaceLogin
        onUpload={handleImageUpload}
        {...userData} // Pass all properties from userData
      />
    </>
  );
};

export default AuthContainer;

import { useState, useEffect } from "react";

const useLocationEnabled = () => {
  const [isLocationEnabled, setIsLocationEnabled] = useState(false);

  useEffect(() => {
    const checkLocationEnabled = () => {
      if ("permissions" in navigator) {
        navigator.permissions
          .query({ name: "geolocation" })
          .then((permissionStatus) => {
            setIsLocationEnabled(permissionStatus.state === "granted");
            permissionStatus.onchange = () => {
              setIsLocationEnabled(permissionStatus.state === "granted");
            };
          });
      } else if ("geolocation" in navigator) {
        navigator.geolocation.getCurrentPosition(
          () => setIsLocationEnabled(true),
          () => setIsLocationEnabled(false)
        );
      } else {
        setIsLocationEnabled(false);
      }
    };

    checkLocationEnabled();
  }, []);

  return isLocationEnabled;
};

export default useLocationEnabled;

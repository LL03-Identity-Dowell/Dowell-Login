const mobileCoordinate = () => {
  return new Promise((resolve, reject) => {
    if ("permissions" in navigator) {
      navigator.permissions.query({ name: "geolocation" }).then((result) => {
        if (result.state === "granted") {
          // Geolocation permission already granted, proceed to get latitude
          navigator.geolocation.getCurrentPosition(
            (position) => {
              const latitude = position.coords.latitude;
              const longitude = position.coords.longitude;
              const location = `${latitude} ${longitude}`;
              resolve(location);
            },
            (error) => {
              reject("Error getting user location");
            }
          );
        } else {
          // Geolocation permission not granted, reject with appropriate message
          reject("Location permission required");
        }
      });
    } else {
      console.error("Permissions API not supported");
      reject("Permissions API not supported");
    }
  });
};

export default mobileCoordinate;

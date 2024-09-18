const Coordinate = () => {
  return new Promise((resolve, reject) => {
    if ("geolocation" in navigator) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const latitude = position.coords.latitude;
          const longitude = position.coords.longitude;
          const location = `${latitude} ${longitude}`;
          resolve(location);
        },
        (error) => {
          //console.error("Error getting user location:", error);
          reject("Location required!");
        }
      );
    } else {
      console.error("Geolocation is not supported");
      reject("Geolocation is not supported");
    }
  });
};

export default Coordinate;

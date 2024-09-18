const dataURItoBlob = (dataURI) => {
  // Split the dataURI into metadata and data parts
  const [metadata, data] = dataURI.split(",");

  // Extract the MIME type from metadata
  const mimeMatch = metadata && metadata.match(/:(.*?);/);
  const mime = mimeMatch && mimeMatch[1];

  // Convert the base64 data to a Blob with the specified MIME type
  return new Blob([atob(data)], { type: mime });
};

export default dataURItoBlob;

// const dataURItoImage = (dataURI) => {
//   return new Promise((resolve, reject) => {
//     try {
//       // Create a new Image object
//       const img = new Image();

//       // Set up event handlers
//       img.onload = () => {
//         // Resolve the promise when the image is successfully loaded
//         resolve(img);
//       };

//       img.onerror = (error) => {
//         // Reject the promise if there's an error loading the image
//         reject(error);
//       };
//       // Set the image source to the provided data URI
//       img.src = dataURI;
//     } catch (error) {
//       // If an exception occurs, reject the promise with the error
//       reject(error);
//     }
//   });
// };

// export default dataURItoImage;

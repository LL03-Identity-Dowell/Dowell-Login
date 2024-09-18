import React, { useEffect } from "react";
import axios from "axios";

const checkRequests = (Wrapped) => {
  function CheckRequests(props) {
    useEffect(() => {
      axios.interceptors.response.use(
        function (response) {
          // Do something with response data
          return response;
        },
        function (error) {
          switch (error.response.status) {
            case 503:
              props.history.push("/503"); //we will redirect user into 503 page
              break;
            default:
              break;
          }
          // Do something with response error
          return Promise.reject(error);
        }
      );
    }); // Add navigate as a dependency to avoid stale closure

    return <Wrapped {...props} />;
  }
  return CheckRequests;
};

export default checkRequests;

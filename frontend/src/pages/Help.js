import React from "react";
import { useState } from "react";
const Help = () => {
  const [helpLoading, setHelpLoading] = useState(true);
  const videoId = "PSmX-A5Cn_E";
  const videoTitle = "Watch a 2 minute video on UX living Lab";

  return (
    <div className="container mx-auto p-2">
      <div className="w-full overflow-hidden">
        <div className=" flex flex-col items-center space-y-2">
          <h2 className="font-semibold text-lg text-white bg-green-500 px-6 py-1 rounded-3xl">
            {videoTitle}
          </h2>
          {helpLoading && (
            <div className="policyFrameSpinner iframespinner">
              {" "}
              <div className="box" style={{ width: "50px", height: "50px" }}>
                {" "}
              </div>
            </div>
          )}
          <div className="aspect-video w-full">
            <iframe
              title="YouTube Video"
              className="w-full h-full rounded-lg"
              src={`https://www.youtube.com/embed/${videoId}`}
              allowFullScreen
              onLoad={() => {
                setHelpLoading(false);
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Help;

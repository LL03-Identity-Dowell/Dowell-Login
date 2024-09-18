import Iframe from "react-iframe";
import { useState } from "react";
const FAQ = () => {
  const [faqLoading, setFaqLoading] = useState(true);
  return (
    <div className="max-w-3xl space-y-2 flex flex-col items-center">
      {faqLoading && (
        <div className="policyFrameSpinner iframespinner">
          {" "}
          <div className="box" style={{ width: "50px", height: "50px" }}>
            {" "}
          </div>
        </div>
      )}
      <Iframe
        url="https://uxlivinglab.com/en/faq/"
        id="myFrame"
        className="py-1 w-full h-[500px] md:h-[350px]"
        display="initial"
        position="relative"
        onLoad={() => {
          setFaqLoading(false);
        }}
      />
    </div>
  );
};

export default FAQ;

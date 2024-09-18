import React from "react";
import Iframe from "react-iframe";
import { useSelector } from "react-redux";
import { Radio } from "react-loader-spinner";

const Chat = () => {
  const { initSession, isLoading } = useSelector((state) => state.init);

  const getChatAppURL = () => {
    const chatSessionID = initSession.qrid_login;
    const baseURL = "https://100096.pythonanywhere.com/chat/login/";
    const chatAppURL = `${baseURL}?session_id=${chatSessionID}`;
    return chatAppURL;
  };

  return (
    <div className="max-w-3xl space-y-2 flex flex-col items-center">
      <h2 className="font-semibold text-lg text-white bg-green-500 px-4 rounded-3xl">
        Chat with UX Living Lab
      </h2>
      {isLoading ? (
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
        <Iframe
          url={getChatAppURL()}
          id="chatAppFrame"
          className="w-full h-[450px] md:h-[350px]"
          display="initial"
          position="relative"
        />
      )}
    </div>
  );
};

export default Chat;

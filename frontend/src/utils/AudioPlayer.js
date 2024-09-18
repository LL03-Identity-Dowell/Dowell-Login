import React, { useEffect, useRef } from "react";

const AudioPlayer = ({ url }) => {
  const audioRef = useRef(null);

  useEffect(() => {
    const audioElement = audioRef.current;
    const updateVisualizer = () => {
      // Forces a re-render
      audioElement.style.display = "none";
      //audioElement.offsetHeight;
      audioElement.style.display = "";
    };

    audioElement.addEventListener("timeupdate", updateVisualizer);
    return () => {
      audioElement.removeEventListener("timeupdate", updateVisualizer);
    };
  }, []);

  return (
    <div className="audioPlayer">
      <audio ref={audioRef} src={url} controls />
    </div>
  );
};

export default AudioPlayer;

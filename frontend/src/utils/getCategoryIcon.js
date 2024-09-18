import {
  RiLoginCircleLine,
  RiMessage2Line,
  RiShieldUserLine,
  RiQuestionLine,
  RiQuestionAnswerLine,
} from "react-icons/ri";

export const getCategoryIcon = (category) => {
  switch (category) {
    case "LogIn":
      return RiLoginCircleLine;
    case "Chat":
      return RiMessage2Line;
    case "Policy":
      return RiShieldUserLine;
    case "Help":
      return RiQuestionLine;
    case "FAQ":
      return RiQuestionAnswerLine;
    default:
      return null;
  }
};

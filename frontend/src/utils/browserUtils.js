export const detectBrowser = () => {
  const userAgent = navigator.userAgent;
  const isFirefox = userAgent.includes("Firefox");
  const isChrome = userAgent.includes("Chrome");
  const isSafari = userAgent.includes("Safari");
  const isIE = userAgent.includes("Trident") || userAgent.includes("MSIE");

  if (isFirefox) {
    return "Firefox";
  } else if (isChrome) {
    return "Chrome";
  } else if (isSafari) {
    return "Safari";
  } else if (isIE) {
    return "Internet Explorer";
  } else {
    return "Unknown browser";
  }
};

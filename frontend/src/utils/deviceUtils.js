import { isMobile, isTablet, isDesktop, osName } from "react-device-detect";

export function getOperatingSystem() {
  return osName; // Retrieves the user's operating system
}

export function getDeviceType() {
  let device;
  if (isMobile) {
    device = "Mobile";
  } else if (isTablet) {
    device = "Tablet";
  } else if (isDesktop) {
    device = "Desktop";
  } else {
    device = "Unknown";
  }
  return device;
}

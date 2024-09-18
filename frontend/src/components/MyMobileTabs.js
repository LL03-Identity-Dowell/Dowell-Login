import React, { useState } from "react";
import { Tab } from "@headlessui/react";
import LogIn from "./LogIn";
import MobileLog from "./MobileLog";
import Chat from "../pages/Chat";
import Policy from "../pages/Policy";
import Help from "../pages/Help";
import FAQ from "../pages/FAQ";
import { getCategoryIcon } from "../utils/getCategoryIcon";
import { MdClose } from "react-icons/md";
import { FiMenu } from "react-icons/fi";
import sideImage from "../assets/images/sideImage.webp";
import { useMediaQuery } from "react-responsive";
import DoWellVerticalLogo from "../assets/images/Dowell-logo-Vertical.jpeg";

function classNames(...classes) {
  return classes.filter(Boolean).join(" ");
}

const MyMobileTabs = () => {
  const [tabMenuOpen, setTabMenuOpen] = useState(false);
  const [selectedTab, setSelectedTab] = useState(0);

  // Use media queries to determine the screen size
  const isMobile = useMediaQuery({ maxWidth: 767 });

  const toggleTabMenu = () => {
    setTabMenuOpen(!tabMenuOpen);
  };

  const categories = [
    { id: 1, title: "LogIn", content: <MobileLog /> },
    { id: 2, title: "Chat", content: <Chat /> },
    { id: 3, title: "Policy", content: <Policy /> },
    { id: 4, title: "Help", content: <Help /> },
    { id: 5, title: "FAQ", content: <FAQ /> },
  ];

  return (
    <Tab.Group>
      <div className="w-full max-w-3xl mx-auto md:py-2 sm:px-0">
        <div className="relative items-center md:flex md:flex-row">
          <div className="flex justify-between items-center">
            {isMobile ? (
              <img
                src={DoWellVerticalLogo}
                alt="DoWell logo"
                className="h-14 w-14 drop md:h-full rounded-lg md:w-32 drop-shadow-lg border border-solid border-black"
              />
            ) : (
              <img
                src={sideImage}
                alt="DoWell logo"
                className="mr-2 h-14 w-14 drop md:h-full rounded-lg md:w-32 drop-shadow-lg border border-solid border-black"
              />
            )}

            <div className="md:hidden">
              <button
                type="button"
                onClick={toggleTabMenu}
                className="p-2 focus:outline-none"
              >
                {tabMenuOpen ? (
                  <MdClose
                    style={{
                      color: "#7b7b7b",
                      width: "40px",
                      height: "40px",
                    }}
                  />
                ) : (
                  <FiMenu
                    style={{
                      color: "#7b7b7b",
                      width: "40px",
                      height: "40px",
                    }}
                  />
                )}
              </button>
            </div>
          </div>

          <div className="md:flex-grow">
            <Tab.List className="rounded-xl p-1">
              <div
                className={`${
                  tabMenuOpen
                    ? "block space-y-2"
                    : "hidden md:flex md:w-full md:space-x-2"
                } bg-gray-700 p-1 rounded-xl items-center justify-center`}
              >
                {categories.map((category, index) => {
                  const Icon = getCategoryIcon(category.title);
                  return (
                    <Tab
                      key={category.id}
                      onClick={() => {
                        setSelectedTab(index);
                        setTabMenuOpen(false);
                      }}
                      className={classNames(
                        "w-full items-center h-12 rounded-2xl md:py-2 md:px-2 text-sm font-medium leading-3 text-green-500 bg-gray-600",
                        "focus:outline-none border-r-2 border-b-2 border-red-800",
                        selectedTab === index
                          ? "bg-green-400 text-white"
                          : "text-green-500 hover:bg-green-400 hover:text-white"
                      )}
                    >
                      <div className="flex items-center justify-center space-x-1">
                        {Icon && <Icon className="w-4 h-4 md:w-6 md:h-6" />}
                        <span>{category.title}</span>
                      </div>
                    </Tab>
                  );
                })}
              </div>
            </Tab.List>
            <Tab.Panels>
              {categories.map((category, index) => (
                <Tab.Panel key={category.id}>
                  <div
                    className={`rounded-xl bg-white ring-white ring-opacity-60 ring-offset-2
                     ring-offset-green-400 focus:outline-none focus:ring-2`}
                  >
                    <ul>
                      <li
                        key={category.id}
                        className={`relative rounded-md hover:bg-gray-100 ${
                          selectedTab !== index && "hidden"
                        }`}
                      >
                        <div className="text-sm font-medium leading-5">
                          <span>{getCategoryIcon(category.title)}</span>
                          {category.content}
                        </div>
                      </li>
                    </ul>
                  </div>
                </Tab.Panel>
              ))}
            </Tab.Panels>
          </div>
        </div>
      </div>
    </Tab.Group>
  );
};

export default MyMobileTabs;

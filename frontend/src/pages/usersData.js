import React from "react";
import CanvasJSReact from "@canvasjs/react-charts";

const CanvasJSChart = CanvasJSReact.CanvasJSChart;

const UsersData = ({ resp }) => {
  const lineGraphData = {
    animationEnabled: true,
    exportEnabled: true,
    theme: "light2",
    title: {
      text: "Line Chart",
      suffix: "%",
    },
    axisX: {
      title: "Date",
      prefix: "D",
    },
    axisY: {
      title: "Value",
    },
    data: [
      {
        type: "spline",
        showInLegend: true,
        name: "Living Lab Admin",
        dataPoints: [
          { label: 1, y: 8 },
          { label: 2, y: 12 },
          { label: 3, y: 76 },
          { label: 4, y: 28 },
          { label: 5, y: 34 },
          { label: 6, y: 67 },
          { label: 7, y: 75 },
        ],
        color: "#FF4069",
      },
      {
        type: "spline",
        showInLegend: true,
        name: "Exhibitoe Form",
        dataPoints: [
          { label: 1, y: 81 },
          { label: 2, y: 29 },
          { label: 3, y: 64 },
          { label: 4, y: 82 },
          { label: 5, y: 4 },
          { label: 6, y: 65 },
          { label: 7, y: 33 },
        ],
        color: "cyan",
      },
      {
        type: "spline",
        showInLegend: true,
        name: "Workflow AI",
        dataPoints: [
          { label: 1, y: 43 },
          { label: 2, y: 26 },
          { label: 3, y: 62 },
          { label: 4, y: 23 },
          { label: 5, y: 45 },
          { label: 6, y: 87 },
          { label: 7, y: 32 },
        ],
        color: "blue",
      },
    ],
  };
  const barChartData = {
    exportEnabled: true,
    animationEnabled: true,
    theme: "light2",
    title: {
      text: "Product Wise Users",
    },
    data: [
      {
        type: "column",
        showInLegend: true,
        name: "Team Members",
        dataPoints: [
          {
            label: "Exhibitoe form",
            y: 9,
          },
          {
            label: "Living Lab Admin",
            y: 15,
          },
          { label: "Workflow AI", y: 29 },
        ],
        color: "#4F81BD",
      },
      {
        type: "column",
        showInLegend: true,
        name: "Users",
        dataPoints: [
          { label: "Exhibitoe form", y: 45 },
          {
            label: "Living Lab Admin",
            y: 67,
          },
          { label: "Workflow AI", y: 12 },
        ],
        color: "black",
      },
      {
        type: "column",
        showInLegend: true,
        name: "Public Members",
        dataPoints: [
          {
            label: "Exhibitoe form",
            y: 34,
          },
          {
            label: "Living Lab Admin",
            y: 98,
          },
          {
            label: "Workflow AI",
            y: 43,
          },
        ],
        color: "green",
      },
    ],
  };
  const pieChartData = {
    exportEnabled: true,
    animationEnabled: true,
    theme: "light2",
    title: {
      text: "Live User",
    },
    data: [
      {
        type: "pie",
        startAngle: 75,
        toolTipContent: "<b>{label}</b> {y}%",
        showInLegend: true,
        legendText: "{label}",
        indexLabelFontSize: 14,
        indexLabel: "{label} - {y}%",
        dataPoints: [
          {
            label: "Team Members",
            y: 18,
            color: "#4F81BD",
          },
          { label: "User", y: 49, color: "#C0504D" },
          {
            label: "Public Member",
            y: 9,
            color: "#9BBB59",
          },
          { label: "Owner", y: 19, color: "cyan" },
        ],
      },
    ],
  };
  return (
    <div className="flex flex-wrap justify-center items-center">
      {/* Line Graph */}
      <div className="w-full lg:w-3/4 p-2">
        <div className="bg-white rounded-lg shadow-lg">
          <CanvasJSChart options={lineGraphData} />
        </div>
      </div>

      {/* Pie Chart and Bar Chart */}
      <div className="w-full md:w-3/4">
        <div className="flex flex-wrap justify-center items-center">
          {/* Pie Chart */}
          <div className="w-full md:w-1/2 p-2">
            <div className="bg-white rounded-lg shadow-lg">
              <CanvasJSChart options={pieChartData} />
            </div>
          </div>

          {/* Bar Chart */}
          <div className="w-full md:w-1/2 p-2">
            <div className="bg-white rounded-lg shadow-lg">
              <CanvasJSChart options={barChartData} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UsersData;

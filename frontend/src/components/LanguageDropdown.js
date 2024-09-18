import React from "react";
import Select from "react-select";
import languages from "iso-639-1";

const languageOptions = languages.getAllCodes().map((code) => ({
  value: code,
  label: languages.getName(code),
}));

const LanguageDropdown = ({
  selectedLanguage,
  onLanguageChange,
  setActivity,
}) => {
  const handleChange = (selectedOption) => {
    onLanguageChange(selectedOption.value);
  };

  return (
    <Select
      options={languageOptions}
      value={languageOptions.find(
        (option) => option.value === selectedLanguage
      )}
      onChange={handleChange}
      onFocus={() => {
        setActivity(true);
      }}
    />
  );
};

export default LanguageDropdown;

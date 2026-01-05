import React, { useEffect, useState } from "react";
import Button from "./Button";

export default function ThemeToggle() {
  const [dark, setDark] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("safeops_theme");
    const isDark = saved ? saved === "dark" : true;
    setDark(isDark);
    document.documentElement.classList.toggle("dark", isDark);
  }, []);

  function toggle() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("safeops_theme", next ? "dark" : "light");
  }

  return (
    <Button variant="soft" onClick={toggle} className="px-3 py-2">
      {dark ? "🌙 Dark" : "☀️ Light"}
    </Button>
  );
}

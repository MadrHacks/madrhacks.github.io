// Change logo based on theme


function getPathOfTheme(path, currentTheme) {
  const reColor = /(green|white)/;
  var newPath = null;
  try {
    const pathSplit = path.split(reColor);
    const color = currentTheme === "dark" ? "white" : "green";

    newPath = pathSplit[0] + color + pathSplit[2];
  } catch (e) {
    newPath = path;
  }

  return newPath;
}

function switchLogoTo(theme) {
  var logoHead = document.getElementById("logo-header");
  var logoHome = document.getElementById("logo-home");

  if (logoHead) {
    const headPath = logoHead.src;
    logoHead.src = getPathOfTheme(headPath, theme);
  }
  if (logoHome) {
    const homePath = logoHome.src;
    logoHome.src = getPathOfTheme(homePath, theme);
  }
};

function initLogo(isDark) {
  const currentTheme = isDark ? "dark" : "light";
  switchLogoTo(currentTheme);
}

try {
  initLogo(isDark);

  // Listener to change logo color
  themeToggle.addEventListener("click", () => {
    const changeToDark = document.body.classList.contains("dark-theme");
    if (changeToDark) {
      switchLogoTo("dark");
    } else {
      switchLogoTo("light");
    }
  });
} catch (e) {
  console.log(e);
}

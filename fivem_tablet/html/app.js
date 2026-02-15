const overlay = document.getElementById("overlay");
const frame = document.getElementById("appFrame");
const closeBtn = document.getElementById("closeBtn");

function postClose() {
  const resourceName =
    typeof GetParentResourceName === "function" ? GetParentResourceName() : "fivem_tablet";
  return fetch(`https://${resourceName}/close`, {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=UTF-8" },
    body: JSON.stringify({})
  }).catch(() => {});
}

window.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data.action !== "setVisible") return;

  if (data.visible) {
    if (data.url && frame.src !== data.url) {
      frame.src = data.url;
    }
    overlay.classList.remove("hidden");
  } else {
    overlay.classList.add("hidden");
  }
});

closeBtn.addEventListener("click", () => {
  postClose();
});
closeBtn.addEventListener("mousedown", () => {
  postClose();
});
closeBtn.addEventListener("touchstart", () => {
  postClose();
});

window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    event.preventDefault();
    postClose();
  }
});

const overlay = document.getElementById("overlay");
const frame = document.getElementById("appFrame");
const closeBtn = document.getElementById("closeBtn");
const resourceName =
  typeof GetParentResourceName === "function" ? GetParentResourceName() : "fivem_tablet_asw";

function postNui(endpoint, payload) {
  return fetch(`https://${resourceName}/${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=UTF-8" },
    body: JSON.stringify(payload || {})
  });
}

function postClose() {
  return postNui("close", {}).catch(() => {});
}

window.addEventListener("message", (event) => {
  const data = event.data || {};

  if (data.action !== "setVisible") return;

  if (data.url && frame.src !== data.url) {
    frame.src = data.url;
  }

  if (data.visible) {
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

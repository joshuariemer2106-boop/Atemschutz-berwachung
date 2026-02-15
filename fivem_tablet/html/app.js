const overlay = document.getElementById("overlay");
const frame = document.getElementById("appFrame");
const closeBtn = document.getElementById("closeBtn");

function postClose() {
  fetch(`https://${GetParentResourceName()}/close`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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

closeBtn.addEventListener("click", postClose);

window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    event.preventDefault();
    postClose();
  }
});

const mediaSelector = "audio, video";

function removeDownloadControls(node) {
  if (!(node instanceof Element)) return;
  for (const link of node.querySelectorAll("[download]")) link.removeAttribute("download");
  if (node.hasAttribute("download")) node.removeAttribute("download");
  const media = node.matches(mediaSelector) ? [node] : node.querySelectorAll(mediaSelector);
  for (const player of media) {
    player.setAttribute("controlslist", "nodownload noremoteplayback");
    player.setAttribute("disablepictureinpicture", "");
  }
}

removeDownloadControls(document.body);
new MutationObserver((changes) => {
  for (const change of changes) {
    if (change.type === "attributes") change.target.removeAttribute("download");
    for (const node of change.addedNodes) removeDownloadControls(node);
  }
}).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["download"] });

document.addEventListener("contextmenu", (event) => {
  if (event.target.closest("img, audio, video")) event.preventDefault();
});
document.addEventListener("dragstart", (event) => {
  if (event.target.closest("img, audio, video")) event.preventDefault();
});

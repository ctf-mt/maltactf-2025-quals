import { Webamp5, SKIN_ENGINES } from "./WebampModern.js";
import SkinEngineWAL from "./skin/SkinEngine_WAL.js";

SkinEngineWAL.canProcess = () => true; // process everything using the WAL engine
SKIN_ENGINES.push(SkinEngineWAL);

const webamp = new Webamp5(document.getElementById("web-amp"), {
    skin: "assets/winamp_classic.wal",
    tracks: ["assets/dreamscape.mp3"]
});

const queryParams = new URLSearchParams(window.location.search);
if (queryParams.has("skin")) {
    const skinUrl = queryParams.get("skin");
    webamp.switchSkin(skinUrl);
}

["dragenter", "dragover", "dragleave", "drop"].forEach(e => {
    document.addEventListener(e, evt => {
        evt.preventDefault();
        evt.stopPropagation();
    });
});

document.addEventListener("drop", e => {
    const files = Array.from(e.dataTransfer.files);
    if (!files.length) {
        return;
    }

    e.preventDefault();
    document.getElementById("drag-zone").style.display = "none";

    const blob = new Blob(files, { type: "application/zip" });
    const blobUrl = URL.createObjectURL(blob);
    webamp.switchSkin(blobUrl);
});
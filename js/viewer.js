// Flip this after the wedding
const PHOTOS_ENABLED = false;

// Where the encrypted assets live
const PHOTOS_MANIFEST_URL = "/photos/manifest.json";

// DOM
const photosLockEl = document.getElementById("photosLock");
const unlockForm = document.getElementById("unlockForm");
const unlockPasswordEl = document.getElementById("unlockPassword");
const unlockStatusEl = document.getElementById("unlockStatus");

const placeholderEl = document.getElementById("photosPlaceholder");
const galleryEl = document.getElementById("photosGallery");

const lightboxImg = document.getElementById("lightboxImg");
const photoCounter = document.getElementById("photoCounter");
const photoCaption = document.getElementById("photoCaption");
const modalEl = document.getElementById("photoModal");
const modal = modalEl ? new bootstrap.Modal(modalEl, {
    backdrop: true,
    keyboard: true,
    focus: true
}) : null;

const prevBtn = document.getElementById("prevBtn");
const nextBtn = document.getElementById("nextBtn");
const prevBtn2 = document.getElementById("prevBtn2");
const nextBtn2 = document.getElementById("nextBtn2");

// Download button (injected into modal footer if missing)
let downloadBtn = document.getElementById("downloadBtn");
if (!downloadBtn && modalEl) {
    const footer = modalEl.querySelector(".modal-footer");
    if (footer) {
        const a = document.createElement("a");
        a.id = "downloadBtn";
        a.className = "btn btn-primary";
        a.textContent = "Download";
        a.setAttribute("download", "photo.jpg");
        a.href = "#";
        footer.appendChild(a);
        downloadBtn = a;
    }
}

let photos = []; // { url: "blob:...", caption: "", mime: "...", filename?: "..." }
let currentIndex = 0;

// ---------- helpers ----------
function b64ToBytes(b64) {
    // Accept standard and URL-safe base64, with or without padding
    let s = String(b64).replace(/-/g, "+").replace(/_/g, "/").trim();
    const pad = s.length % 4;
    if (pad) s += "=".repeat(4 - pad);

    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

function bytesToB64(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}

async function fetchJson(url) {
    const res = await fetch(url, {
        cache: "no-store"
    });
    if (!res.ok) throw new Error(`Failed to fetch ${url} (${res.status})`);
    return res.json();
}

async function fetchAsBytes(url) {
    const res = await fetch(url, {
        cache: "no-store"
    });
    if (!res.ok) throw new Error(`Failed to fetch ${url} (${res.status})`);
    return new Uint8Array(await res.arrayBuffer());
}

function toArrayBuffer(u8) {
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

// ---------- crypto: PBKDF2 -> AES-GCM key ----------
async function deriveAesKeyFromPassword({
    password,
    saltBytes,
    iterations
}) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey({
            name: "PBKDF2",
            salt: saltBytes,
            iterations,
            hash: "SHA-256",
        },
        baseKey, {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["decrypt"]
    );
}

async function decryptAesGcm({
    encryptedBytes,
    ivBytes,
    key
}) {
    const plaintext = await crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: toArrayBuffer(ivBytes)
        },
        key,
        toArrayBuffer(encryptedBytes)
    );
    return new Uint8Array(plaintext);
}

// ---------- gallery/lightbox ----------
function setLightbox(index) {
    currentIndex = (index + photos.length) % photos.length;
    const p = photos[currentIndex];
    lightboxImg.src = p.url;
    photoCounter.textContent = `(${currentIndex + 1}/${photos.length})`;
    photoCaption.textContent = p.caption || "";

    if (downloadBtn) {
        downloadBtn.href = p.url;
        downloadBtn.setAttribute("download", p.filename);
        downloadBtn.setAttribute("type", p.mime);
    }
}

function openLightbox(index) {
    setLightbox(index);
    modal.show();
}

function nextPhoto() {
    setLightbox(currentIndex + 1);
}

function prevPhoto() {
    setLightbox(currentIndex - 1);
}

function renderGallery() {
    galleryEl.innerHTML = "";
    photos.forEach((p, idx) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "photo-thumb p-0";
        btn.setAttribute("aria-label", `Open photo ${idx + 1}`);
        btn.innerHTML = `<img src="${p.url}" alt="Wedding photo ${idx + 1}">`;
        btn.addEventListener("click", () => openLightbox(idx));
        galleryEl.appendChild(btn);
    });
}

function wireControlsOnce() {
    prevBtn?.addEventListener("click", prevPhoto);
    nextBtn?.addEventListener("click", nextPhoto);
    prevBtn2?.addEventListener("click", prevPhoto);
    nextBtn2?.addEventListener("click", nextPhoto);

    function onKeydown(e) {
        if (e.key === "ArrowLeft") prevPhoto();
        if (e.key === "ArrowRight") nextPhoto();
        if (e.key === "Escape") modal?.hide();
    }

    modalEl?.addEventListener("shown.bs.modal", () => {
        document.addEventListener("keydown", onKeydown);
    });
    modalEl?.addEventListener("hidden.bs.modal", () => {
        document.removeEventListener("keydown", onKeydown);
    });

    // Clean up the focused image when closing to avoid weird "stuck" states on some mobile browsers
    modalEl?.addEventListener("hidden.bs.modal", () => {
        lightboxImg.removeAttribute("src");
        photoCaption.textContent = "";
        photoCounter.textContent = "";
    });
}

// ---------- main loading ----------
async function loadAndDecryptPhotos(password) {
    // Manifest shape:
    // {
    //   "kdf": { "name":"PBKDF2", "hash":"SHA-256", "iterations": 210000, "saltB64":"..." },
    //   "photos": [ { "blobUrl":"/photos/001.bin", "ivB64":"...", "mime":"image/jpeg", "caption":"...", "filename":"..." }, ... ]
    // }
    const manifest = await fetchJson(PHOTOS_MANIFEST_URL);

    const saltBytes = b64ToBytes(manifest.kdf.saltB64);
    const iterations = manifest.kdf.iterations;

    const key = await deriveAesKeyFromPassword({
        password,
        saltBytes,
        iterations
    });

    const decrypted = [];
    for (const item of manifest.photos) {
        const encryptedBytes = await fetchAsBytes(item.blobUrl);
        const ivBytes = b64ToBytes(item.ivB64);

        const plainBytes = await decryptAesGcm({
            encryptedBytes,
            ivBytes,
            key
        });
        const blob = new Blob([plainBytes], {
            type: item.mime || "image/jpeg"
        });
        const url = URL.createObjectURL(blob);

        const extFromMime = (item.mime || "").split("/")[1] || "jpg";
        decrypted.push({
            url,
            caption: item.caption || "",
            mime: item.mime || "image/jpeg",
            filename: item.filename || `photo-${decrypted.length + 1}.${extFromMime}`
        });
    }
    return decrypted;
}

function showPlaceholder(text, subtext) {
    placeholderEl.classList.remove("d-none");
    placeholderEl.innerHTML = `
      <div class="h5 mb-2">${text}</div>
      <div class="text-muted">${subtext}</div>
    `;
}

async function initPhotosSection() {
    wireControlsOnce();

    // iOS Safari requires a secure context (HTTPS) for WebCrypto.
    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
        photosLockEl?.classList.remove("d-none");
        galleryEl.classList.add("d-none");
        showPlaceholder("Photos are locked 🔒",
            "This feature requires HTTPS (secure context) to decrypt photos on your device.");
        unlockStatusEl.textContent = "Please open the site over HTTPS to unlock photos.";
        return;
    }

    if (!PHOTOS_ENABLED) {
        // Before the wedding: no lock, no downloads
        photosLockEl?.classList.add("d-none");
        galleryEl.classList.add("d-none");
        //showPlaceholder("Photos will appear here soon 📸", "Check back after the wedding day.");
        return;
    }

    // After wedding: show lock form, but keep gallery hidden
    photosLockEl?.classList.remove("d-none");
    galleryEl.classList.add("d-none");
    showPlaceholder("Photos are locked 🔒", "Enter the password below to unlock.");

    unlockForm?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const password = unlockPasswordEl.value;

        unlockStatusEl.textContent = "Unlocking…";

        try {
            // cleanup old blob URLs if re-unlocking
            for (const p of photos) URL.revokeObjectURL(p.url);
            photos = [];

            photos = await loadAndDecryptPhotos(password);

            if (!photos.length) throw new Error("No photos found.");

            renderGallery();
            photosLockEl.classList.add("d-none");
            placeholderEl.classList.add("d-none");
            galleryEl.classList.remove("d-none");
            unlockStatusEl.textContent = "";
        } catch (err) {
            console.error(err);
            const msg = (err && err.message) ? err.message : String(err);
            if (/Failed to fetch|\(404\)|\(403\)|\(500\)/i.test(msg)) {
                unlockStatusEl.textContent =
                    "Could not download the photos/manifest on this device. Please try again later.";
            } else if (/OperationError|DataError|decrypt/i.test(msg)) {
                unlockStatusEl.textContent =
                    "Wrong password (or incompatible encryption). Please try again.";
            } else {
                unlockStatusEl.textContent = "Unlock failed. Please try again.";
            }
        }
    });
}

initPhotosSection();
// Flip this on once public/photos/ has been generated and deployed. Kept false
// through the Cloudflare migration so guests get the "coming soon" placeholder
// instead of an unlock form over a 404.
const PHOTOS_ENABLED = false;

// Where the encrypted assets live
const PHOTOS_MANIFEST_URL = "/photos/manifest.json";

// Manifest shape this viewer understands. Must match MANIFEST_VERSION in
// encrypt-photos.mjs, so a half-deployed gallery fails loudly.
const MANIFEST_VERSION = 3;

// Optional external link for downloading the whole gallery in one go. Leave
// empty and the link stays hidden.
const ARCHIVE_URL = "";

// How many full-size images stay decrypted at once. The full tier averages
// 6.0 MP, so each one costs ~22.9 MB of bitmap if the browser keeps it decoded --
// an unbounded cache is what runs phones out of memory. 3 is the natural floor:
// prefetching is +/-1, so current + both neighbours fits exactly and every
// navigation still hits a warm cache.
const MAX_FULL_CACHED = 3;

// Concurrent fetch+decrypt jobs.
const MAX_CONCURRENT = 4;

// Start fetching thumbnails this far outside the viewport.
const THUMB_ROOT_MARGIN = "600px";

// DOM
const photosLockEl = document.getElementById("photosLock");
const unlockForm = document.getElementById("unlockForm");
const unlockPasswordEl = document.getElementById("unlockPassword");
const unlockStatusEl = document.getElementById("unlockStatus");

const placeholderEl = document.getElementById("photosPlaceholder");
const thanksEl = document.getElementById("photosThanks");
const galleryEl = document.getElementById("photosGallery");
const archiveWrapEl = document.getElementById("photosArchive");
const archiveLinkEl = document.getElementById("photosArchiveLink");

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

// Each entry holds manifest metadata plus whatever we have decrypted so far:
// { blobUrl, ivB64, thumbUrl, thumbIvB64, mime, caption, filename,
//   thumbObjectUrl, fullObjectUrl, thumbPromise, fullPromise }
let photos = [];
let cryptoKey = null;
let buildId = "";
let currentIndex = 0;

// Bumped on every lightbox navigation. A decrypt that resolves with a stale
// token is discarded, so holding the arrow key can't leave a neighbour's image
// on screen.
let lightboxToken = 0;

// Indices of photos whose full tier is decrypted, least-recently-used first.
const fullLru = [];

let thumbObserver = null;

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

async function fetchJson(url) {
    // no-store: the manifest is how we discover a new build, so it must never
    // come from cache.
    const res = await fetch(url, {
        cache: "no-store"
    });
    if (!res.ok) throw new Error(`Failed to fetch ${url} (${res.status})`);
    return res.json();
}

async function fetchAsBytes(url) {
    // Cached normally. Blob filenames repeat across builds with entirely
    // different ciphertext, so withBuild() below is what keeps a stale blob from
    // being paired with this build's salt.
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch ${url} (${res.status})`);
    return new Uint8Array(await res.arrayBuffer());
}

function withBuild(url) {
    return buildId ? `${url}?v=${encodeURIComponent(buildId)}` : url;
}

function toArrayBuffer(u8) {
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

// ---------- job queue ----------
// Two-tier so a tapped photo never queues behind a backlog of thumbnails.
const jobQueue = {
    high: [],
    low: []
};
let activeJobs = 0;

function enqueue(job, priority) {
    return new Promise((resolve, reject) => {
        jobQueue[priority].push({
            job,
            resolve,
            reject
        });
        pumpQueue();
    });
}

function pumpQueue() {
    while (activeJobs < MAX_CONCURRENT) {
        const next = jobQueue.high.shift() || jobQueue.low.shift();
        if (!next) return;

        activeJobs++;
        next.job().then(next.resolve, next.reject).finally(() => {
            activeJobs--;
            pumpQueue();
        });
    }
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

async function decryptToObjectUrl({
    url,
    ivB64,
    mime
}) {
    const encryptedBytes = await fetchAsBytes(withBuild(url));
    const plainBytes = await decryptAesGcm({
        encryptedBytes,
        ivBytes: b64ToBytes(ivB64),
        key: cryptoKey
    });
    return URL.createObjectURL(new Blob([plainBytes], {
        type: mime || "image/jpeg"
    }));
}

// ---------- tiered loading ----------
function ensureThumb(index) {
    const p = photos[index];
    if (p.thumbObjectUrl) return Promise.resolve(p.thumbObjectUrl);

    if (!p.thumbPromise) {
        p.thumbPromise = enqueue(() => decryptToObjectUrl({
            url: p.thumbUrl,
            ivB64: p.thumbIvB64,
            mime: p.mime
        }), "low").then(url => {
            p.thumbObjectUrl = url;
            return url;
        }, err => {
            p.thumbPromise = null; // allow a later retry
            throw err;
        });
    }
    return p.thumbPromise;
}

function ensureFull(index, priority = "high") {
    const p = photos[index];
    if (p.fullObjectUrl) {
        touchFullLru(index);
        return Promise.resolve(p.fullObjectUrl);
    }

    if (!p.fullPromise) {
        p.fullPromise = enqueue(() => decryptToObjectUrl({
            url: p.blobUrl,
            ivB64: p.ivB64,
            mime: p.mime
        }), priority).then(url => {
            p.fullObjectUrl = url;
            p.fullPromise = null;
            touchFullLru(index);
            return url;
        }, err => {
            p.fullPromise = null;
            throw err;
        });
    }
    return p.fullPromise;
}

// Keeps at most MAX_FULL_CACHED full images alive, revoking the object URLs of
// the rest so the browser can free their bitmaps.
function touchFullLru(index) {
    const at = fullLru.indexOf(index);
    if (at !== -1) fullLru.splice(at, 1);
    fullLru.push(index);

    while (fullLru.length > MAX_FULL_CACHED) {
        const evicted = fullLru.shift();

        // Never evict what is currently on screen; only one index can match, so
        // the next iteration still makes progress.
        if (evicted === currentIndex) {
            fullLru.push(evicted);
            continue;
        }

        const p = photos[evicted];
        if (p && p.fullObjectUrl) {
            URL.revokeObjectURL(p.fullObjectUrl);
            p.fullObjectUrl = null;
        }
    }
}

function prefetchNeighbours(index) {
    for (const delta of [1, -1]) {
        const n = (index + delta + photos.length) % photos.length;
        if (n === index) continue;
        ensureFull(n, "low").catch(() => {}); // best effort
    }
}

function releaseAll() {
    for (const p of photos) {
        if (p.thumbObjectUrl) URL.revokeObjectURL(p.thumbObjectUrl);
        if (p.fullObjectUrl) URL.revokeObjectURL(p.fullObjectUrl);
    }
    photos = [];
    fullLru.length = 0;

    if (thumbObserver) {
        thumbObserver.disconnect();
        thumbObserver = null;
    }
}

// ---------- gallery/lightbox ----------
function setDownloadTarget(p) {
    if (!downloadBtn) return;

    if (!p || !p.fullObjectUrl) {
        downloadBtn.classList.add("disabled");
        downloadBtn.setAttribute("aria-disabled", "true");
        downloadBtn.removeAttribute("href");
        return;
    }

    downloadBtn.classList.remove("disabled");
    downloadBtn.removeAttribute("aria-disabled");
    downloadBtn.href = p.fullObjectUrl;
    downloadBtn.setAttribute("download", p.filename);
    downloadBtn.setAttribute("type", p.mime);
}

async function setLightbox(index) {
    currentIndex = (index + photos.length) % photos.length;
    const token = ++lightboxToken;
    const p = photos[currentIndex];

    photoCounter.textContent = `(${currentIndex + 1}/${photos.length})`;
    photoCaption.textContent = p.caption || "";

    // Show whatever is already decrypted so the modal is never blank.
    if (p.fullObjectUrl) lightboxImg.src = p.fullObjectUrl;
    else if (p.thumbObjectUrl) lightboxImg.src = p.thumbObjectUrl;
    else lightboxImg.removeAttribute("src");

    setDownloadTarget(p.fullObjectUrl ? p : null);

    try {
        const url = await ensureFull(currentIndex);
        if (token !== lightboxToken) return; // navigated away meanwhile

        lightboxImg.src = url;
        setDownloadTarget(photos[currentIndex]);
        prefetchNeighbours(currentIndex);
    } catch (err) {
        if (token !== lightboxToken) return;
        console.error(`Photo ${currentIndex + 1} failed to load`, err);
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

function onThumbsVisible(entries) {
    for (const entry of entries) {
        if (!entry.isIntersecting) continue;

        const el = entry.target;
        const idx = Number(el.dataset.index);
        thumbObserver.unobserve(el);

        ensureThumb(idx).then(url => {
            const img = el.querySelector("img");
            if (img) img.src = url;
            el.classList.remove("photo-thumb--loading");
        }).catch(err => {
            // Leave the placeholder in place rather than re-observing, which
            // would spin while the element stays in view.
            el.classList.add("photo-thumb--failed");
            console.error(`Thumbnail ${idx + 1} failed to load`, err);
        });
    }
}

// Renders every tile up front with no image source, so the grid appears at once
// and the observer gets correctly positioned targets. Thumbnails are fetched
// only as tiles approach the viewport.
function renderGallery() {
    galleryEl.innerHTML = "";
    if (thumbObserver) thumbObserver.disconnect();

    const frag = document.createDocumentFragment();

    photos.forEach((p, idx) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "photo-thumb photo-thumb--loading p-0";
        btn.setAttribute("aria-label", `Open photo ${idx + 1}`);
        btn.dataset.index = String(idx);

        // No width/height attributes: thumbnails are no longer a fixed size
        // (portrait and landscape differ), and the tile's CSS aspect-ratio
        // already gives the box a definite size, so there is no layout shift.
        const img = document.createElement("img");
        img.loading = "lazy"; // defers decode of off-screen tiles
        img.decoding = "async";
        img.alt = `Wedding photo ${idx + 1}`;
        btn.appendChild(img);

        btn.addEventListener("click", () => openLightbox(idx));
        frag.appendChild(btn);
    });

    galleryEl.appendChild(frag);

    thumbObserver = new IntersectionObserver(onThumbsVisible, {
        rootMargin: THUMB_ROOT_MARGIN
    });
    galleryEl.querySelectorAll(".photo-thumb").forEach(el => thumbObserver.observe(el));
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

    // Drop the on-screen bitmap when closing. The decrypted blob stays in the
    // LRU, so reopening is instant without holding a decoded image.
    modalEl?.addEventListener("hidden.bs.modal", () => {
        document.removeEventListener("keydown", onKeydown);
        lightboxImg.removeAttribute("src");
        photoCaption.textContent = "";
        photoCounter.textContent = "";
    });
}

// ---------- main loading ----------
// Manifest shape:
// {
//   "version": 2,
//   "build": "22f141cf2233",
//   "kdf": { "name":"PBKDF2", "hash":"SHA-256", "iterations": 210000, "saltB64":"..." },
//   "photos": [ { "blobUrl":"/photos/001.bin", "ivB64":"...",
//                 "thumbUrl":"/photos/001-thumb.bin", "thumbIvB64":"...",
//                 "mime":"image/jpeg", "caption":"..." }, ... ]
// }
async function unlockGallery(password) {
    const manifest = await fetchJson(PHOTOS_MANIFEST_URL);

    if (manifest.version !== MANIFEST_VERSION) {
        throw new Error(
            `Unsupported manifest version ${manifest.version} (expected ${MANIFEST_VERSION}).`
        );
    }

    buildId = manifest.build || "";

    cryptoKey = await deriveAesKeyFromPassword({
        password,
        saltBytes: b64ToBytes(manifest.kdf.saltB64),
        iterations: manifest.kdf.iterations
    });

    photos = manifest.photos.map((item, i) => ({
        blobUrl: item.blobUrl,
        ivB64: item.ivB64,
        thumbUrl: item.thumbUrl,
        thumbIvB64: item.thumbIvB64,
        mime: item.mime || "image/jpeg",
        caption: item.caption || "",
        filename: item.filename || `photo-${i + 1}.jpg`,
        thumbObjectUrl: null,
        fullObjectUrl: null,
        thumbPromise: null,
        fullPromise: null
    }));

    if (!photos.length) throw new Error("No photos found.");

    // Nothing else decrypts at unlock time now, so decrypt one thumbnail here:
    // a wrong password has to fail before we dismiss the form, otherwise it
    // looks like a successful unlock followed by an empty grid.
    await ensureThumb(0);
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

    // After wedding: show lock form, but keep gallery hidden. No placeholder --
    // the lock card in index.html already carries translated copy, and the
    // pre-wedding placeholder text would be wrong now.
    photosLockEl?.classList.remove("d-none");
    placeholderEl.classList.add("d-none");
    galleryEl.classList.add("d-none");

    unlockForm?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const password = unlockPasswordEl.value;

        unlockStatusEl.textContent = "Unlocking…";

        try {
            releaseAll(); // cleanup if re-unlocking
            await unlockGallery(password);

            renderGallery();
            photosLockEl.classList.add("d-none");
            // Text comes from data-i18n-* and is already populated by applyLang(),
            // so this only needs to reveal it.
            thanksEl?.classList.remove("d-none");
            galleryEl.classList.remove("d-none");

            if (ARCHIVE_URL && archiveWrapEl && archiveLinkEl) {
                archiveLinkEl.href = ARCHIVE_URL;
                archiveWrapEl.classList.remove("d-none");
            }

            unlockStatusEl.textContent = "";
        } catch (err) {
            console.error(err);
            // WebCrypto rejects with a DOMException whose useful discriminator is
            // .name ("OperationError"); .message is generic prose. Match on both,
            // or a wrong password falls through to the catch-all message.
            const msg = [err?.name, err?.message].filter(Boolean).join(": ") || String(err);
            if (/manifest version/i.test(msg)) {
                unlockStatusEl.textContent =
                    "The gallery needs to be regenerated. Please let us know!";
            } else if (/Failed to fetch|\(404\)|\(403\)|\(500\)/i.test(msg)) {
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

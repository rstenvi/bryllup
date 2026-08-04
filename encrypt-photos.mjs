#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import {
    spawn
} from "node:child_process";

// Resize settings. Originals are ~12 MB each, far too big to serve from
// GitHub Pages (1 GB hard limit on published sites).
const MAX_DIM = 3000; // long edge, in px; smaller images are left alone
const JPEG_QUALITY = 85;

// Thumbnails for the gallery grid. Fitted inside this box with aspect ratio
// preserved and NO crop -- the grid cell is portrait-shaped and uses
// object-fit: contain, so cropping here would permanently discard pixels.
// A 2:3 source lands at 667x1000, a 3:2 source at 700x467; both comfortably
// cover a 2x retina cell.
const THUMB_BOX_W = 700;
const THUMB_BOX_H = 1000;
const THUMB_QUALITY = 72;

// Bumped whenever the manifest shape or the meaning of its blobs changes, so the
// viewer rejects a stale build instead of rendering it wrongly. v3 = uncropped,
// variable-size thumbnails.
const MANIFEST_VERSION = 3;

// Subdirectory under the output folder that holds the encrypted blobs. Keeps
// manifest.json out of the immutable-cache glob in public/_headers; see the
// comment where blobDir is created. Not part of the manifest contract -- the
// viewer only follows the URLs the manifest hands it.
const BLOB_SUBDIR = "b";

function b64(buf) {
    return buf.toString("base64");
}

function mb(bytes) {
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

// Natural sort so "img-12.jpg" comes before "img-102.jpg"
const collator = new Intl.Collator(undefined, {
    numeric: true,
    sensitivity: "base"
});

async function listFiles(dir) {
    const ents = await fs.readdir(dir, {
        withFileTypes: true
    });
    return ents
        .filter(e => e.isFile())
        .map(e => e.name)
        .filter(name => /\.(jpe?g|png|webp)$/i.test(name))
        .sort(collator.compare)
        .map(name => path.join(dir, name));
}

const INSTALL_HINTS = {
    magick: "brew install imagemagick",
    zip: "zip ships with macOS; check your PATH"
};

function run(cmd, args, opts = {}) {
    return new Promise((resolve, reject) => {
        const proc = spawn(cmd, args, opts);
        const out = [];
        const err = [];

        proc.stdout.on("data", c => out.push(c));
        proc.stderr.on("data", c => err.push(c));
        proc.on("error", e => reject(
            e.code === "ENOENT" ?
            new Error(`\`${cmd}\` not found. ${INSTALL_HINTS[cmd] || ""}`.trim()) :
            e
        ));
        proc.on("close", code => {
            if (code !== 0) {
                reject(new Error(`${cmd} exited ${code}: ${Buffer.concat(err).toString().trim()}`));
                return;
            }
            resolve(Buffer.concat(out));
        });
    });
}

// Downscale to a web-friendly JPEG and return the bytes. Everything becomes
// JPEG since we re-encode anyway, so the manifest mime is always image/jpeg.
function resizeToJpeg(file) {
    return run("magick", [
        file,
        "-auto-orient", // bake in EXIF rotation before metadata is stripped
        "-resize", `${MAX_DIM}x${MAX_DIM}>`, // ">" = only shrink, never enlarge
        "-quality", String(JPEG_QUALITY),
        "-interlace", "JPEG", // progressive: renders top-down while loading
        "-strip", // drop EXIF/GPS/XMP; sources are already sRGB
        "JPEG:-" // write to stdout, no temp files
    ]);
}

// Grid thumbnail: fit inside the box, preserving aspect ratio. No "^" and no
// -extent, so nothing is cropped -- portrait photos keep their full height.
function resizeToThumb(file) {
    return run("magick", [
        file,
        "-auto-orient",
        "-resize", `${THUMB_BOX_W}x${THUMB_BOX_H}>`,
        "-quality", String(THUMB_QUALITY),
        "-interlace", "JPEG",
        "-strip",
        "JPEG:-"
    ]);
}

function deriveKeyPBKDF2(password, salt, iterations) {
    // 32 bytes => AES-256
    return crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
}

function encryptAesGcm(plaintext, key) {
    const iv = crypto.randomBytes(12); // recommended for GCM
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Store as: ciphertext || tag (common pattern)
    return {
        iv,
        out: Buffer.concat([ciphertext, tag])
    };
}

async function main() {
    const argv = process.argv.slice(2);
    const wantArchive = argv.includes("--archive");
    const [inDir, outDir, password] = argv.filter(a => !a.startsWith("--"));

    if (!inDir || !outDir || !password) {
        console.error(
            "Usage: node encrypt-photos.mjs <inputFolder> <outputFolder> <password> [--archive]"
        );
        process.exit(1);
    }

    const iterations = 210000;
    const salt = crypto.randomBytes(16);
    const key = deriveKeyPBKDF2(password, salt, iterations);

    await fs.mkdir(outDir, {
        recursive: true
    });

    // Blobs go in a subdirectory so the Cloudflare _headers globs cannot overlap.
    // Cloudflare merges every matching rule into one header rather than letting
    // the first win, so a flat layout produced the self-contradictory
    // "no-store, public, max-age=31536000, immutable" on manifest.json. With the
    // blobs one level down, /photos/b/* is immutable and the manifest is only
    // matched by its own no-store rule.
    const blobDir = path.join(outDir, BLOB_SUBDIR);
    await fs.mkdir(blobDir, {
        recursive: true
    });

    const files = await listFiles(inDir);
    if (!files.length) {
        console.error("No images found in input folder (jpg/png/webp).");
        process.exit(1);
    }

    const manifest = {
        version: MANIFEST_VERSION,
        // Identifies this build. The salt is regenerated every run, so this is a
        // fresh value each time -- the viewer appends it to blob URLs so a cached
        // blob from an older build can never be paired with this run's salt.
        build: crypto.createHash("sha256").update(salt).digest("hex").slice(0, 12),
        kdf: {
            name: "PBKDF2",
            hash: "SHA-256",
            iterations,
            saltB64: b64(salt),
        },
        photos: []
    };

    // Staging dir for the optional plaintext archive, zipped up at the end.
    const archiveDir = wantArchive ?
        await fs.mkdtemp(path.join(os.tmpdir(), "bryllup-archive-")) :
        null;

    let totalIn = 0;
    let totalFull = 0;
    let totalThumb = 0;

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const fullBytes = await resizeToJpeg(file);

        // Two independent encryptAesGcm calls => two distinct random IVs. Never
        // reuse one IV across both tiers: under a shared key that would leak the
        // XOR of the two plaintexts.
        const full = encryptAesGcm(fullBytes, key);
        const thumb = encryptAesGcm(await resizeToThumb(file), key);

        if (archiveDir) {
            // Keep the photographer's filenames, but the bytes are JPEG now.
            const stem = path.basename(file, path.extname(file));
            await fs.writeFile(path.join(archiveDir, `${stem}.jpg`), fullBytes);
        }

        const id = String(i + 1).padStart(3, "0");
        const fullName = `${id}.bin`;
        const thumbName = `${id}-thumb.bin`;

        await fs.writeFile(path.join(blobDir, fullName), full.out);
        await fs.writeFile(path.join(blobDir, thumbName), thumb.out);

        manifest.photos.push({
            blobUrl: `/photos/${BLOB_SUBDIR}/${fullName}`, // adjust if you host elsewhere
            ivB64: b64(full.iv),
            thumbUrl: `/photos/${BLOB_SUBDIR}/${thumbName}`,
            thumbIvB64: b64(thumb.iv),
            mime: "image/jpeg",
            caption: "" // fill later if you want
        });

        totalIn += (await fs.stat(file)).size;
        totalFull += full.out.length;
        totalThumb += thumb.out.length;
        console.log(
            `[${i + 1}/${files.length}] ${path.basename(file)} -> ${fullName} (${mb(full.out.length)})` +
            ` + ${thumbName} (${mb(thumb.out.length)})`
        );
    }

    await fs.writeFile(path.join(outDir, "manifest.json"), JSON.stringify(manifest, null, 2));

    if (archiveDir) {
        // Deliberately outside outDir so it is never published or committed.
        const zipPath = path.resolve(`photos-${MAX_DIM}px.zip`);
        await fs.rm(zipPath, {
            force: true
        });
        await run("zip", ["-r", "-q", "-X", zipPath, "."], {
            cwd: archiveDir
        });
        await fs.rm(archiveDir, {
            recursive: true,
            force: true
        });
        console.log(`\nArchive: ${zipPath} (${mb((await fs.stat(zipPath)).size)})`);
    }

    console.log(`\nEncrypted ${files.length} images (build ${manifest.build}).`);
    console.log(`  full:  max ${MAX_DIM}px, quality ${JPEG_QUALITY} -> ${mb(totalFull)}`);
    console.log(
        `  thumb: fit ${THUMB_BOX_W}x${THUMB_BOX_H}, quality ${THUMB_QUALITY} -> ${mb(totalThumb)}`
    );
    console.log(`Total: ${mb(totalIn)} -> ${mb(totalFull + totalThumb)}`);
    console.log(`Wrote: ${path.join(outDir, "manifest.json")}`);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
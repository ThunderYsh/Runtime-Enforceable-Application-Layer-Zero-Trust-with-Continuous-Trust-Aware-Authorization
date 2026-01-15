// static/ztna/device_fingerprint.js
(async function () {
    console.log("🔵 Device fingerprint script started.");

    function generateRaw() {
        return [
            navigator.userAgent,
            navigator.language,
            screen.width,
            screen.height,
            screen.colorDepth,
            navigator.hardwareConcurrency,
            Intl.DateTimeFormat().resolvedOptions().timeZone
        ].join("::");
    }

    async function sha256(str) {
        const buffer = new TextEncoder().encode(str);
        const hash = await crypto.subtle.digest("SHA-256", buffer);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    }

    const raw = generateRaw();
    const hash = await sha256(raw);

    console.log("📌 Fingerprint Generated:", hash);

    document.cookie = `device_fp=${hash}; path=/; SameSite=Lax`;
    sessionStorage.setItem("device_fp", hash);
})();

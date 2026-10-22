// Admin panel for the Los Angeles store.
//
// The store data (products, deals, categories, looks, settings) lives in data.bin next to
// the site, encrypted with the site's entry code (see tools/build-protected.mjs). This page
// reads and writes it straight in the GitHub repo that hosts the site, through the GitHub
// API: every save is one commit, built on the latest data so two devices never overwrite
// each other. Product photos are resized here, encrypted the same way, and committed with it.
//
// Sign-in: admin/vault.json holds the GitHub token and the entry code, encrypted with the
// admin password. First-time setup creates it.
(() => {
  "use strict";

  const CONFIG = {
    owner: "askavi8",
    repo: "askavi8.github.io",
    branch: "main",
    dir: "LosAngeles",
    api: "https://api.github.com",
    ...(window.LA_ADMIN_CONFIG || {}),
  };
  const SITE = "../"; // the store, relative to this page
  const DATA_PATH = `${CONFIG.dir}/data.bin`;
  const VAULT_PATH = `${CONFIG.dir}/admin/vault.json`;
  const SITE_ITERATIONS = 150000; // same as the entry screen
  const VAULT_ITERATIONS = 310000;
  const SESSION_KEY = "la_admin_session";
  const MAX_IMAGE = 1000; // px, longest side of an uploaded photo

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const icon = (name, cls = "") => `<svg${cls ? ` class="${cls}"` : ""}><use href="#i-${name}"/></svg>`;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const newId = (prefix) => prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);

  // ---------- bytes & crypto ----------
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const toB64 = (bytes) => {
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const fromB64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  };

  async function pbkdf2(secret, salt, iterations, usages) {
    const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      usages
    );
  }
  const seal = async (key, iv, data) => new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data));
  const unseal = async (key, iv, data) => new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data));

  // the site key: same derivation (and fixed salt) as the build and the entry screen
  let siteSalt = null;
  async function siteKeyFor(code) {
    siteSalt ||= (await sha256(enc.encode("los-angeles-store-preview"))).slice(0, 16);
    return pbkdf2(code, siteSalt, SITE_ITERATIONS, ["encrypt", "decrypt"]);
  }

  // data.bin = [16-byte salt][12-byte IV][ciphertext of the JSON]
  const openData = async (key, bytes) => JSON.parse(dec.decode(await unseal(key, bytes.subarray(16, 28), bytes.subarray(28))));
  async function sealData(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return concat(siteSalt, iv, await seal(key, iv, enc.encode(JSON.stringify(data))));
  }

  // an image file = [12-byte IV][ciphertext]; the IV comes from the content, so the same photo
  // always gives the same file, named by its hash (i/<hash>.<ext>.bin) like the build does
  async function sealImage(key, bytes, ext) {
    const iv = (await sha256(bytes)).slice(0, 12);
    const file = concat(iv, await seal(key, iv, bytes));
    return { file, ref: `i/${hex((await sha256(file)).slice(0, 8))}.${ext}.bin` };
  }

  async function sealVault(password, secrets) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await pbkdf2(password, salt, VAULT_ITERATIONS, ["encrypt"]);
    const data = await seal(key, iv, enc.encode(JSON.stringify(secrets)));
    return JSON.stringify({ v: 1, iterations: VAULT_ITERATIONS, salt: toB64(salt), iv: toB64(iv), data: toB64(data) });
  }
  async function openVault(password, vault) {
    const key = await pbkdf2(password, fromB64(vault.salt), vault.iterations, ["decrypt"]);
    return JSON.parse(dec.decode(await unseal(key, fromB64(vault.iv), fromB64(vault.data))));
  }

  // ---------- state ----------
  const S = {
    token: null,
    code: null,
    key: null,
    data: null,
    view: "products",
    filter: "all",
    query: "",
    lookQuery: "",
  };
  const uploads = new Map(); // ref -> encrypted bytes, waiting for the next save
  let E = null; // the open editor

  // ---------- GitHub API ----------
  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  async function gh(path, { method = "GET", body, raw, token = S.token } = {}) {
    let res;
    try {
      res = await fetch(`${CONFIG.api}/repos/${CONFIG.owner}/${CONFIG.repo}${path ? "/" + path : ""}`, {
        method,
        cache: "no-store",
        headers: {
          Accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new ApiError(0, "אין חיבור לאינטרנט. בדקו את החיבור ונסו שוב.");
    }
    if (!res.ok) {
      let message = "";
      try {
        message = (await res.json()).message || "";
      } catch {
        /* no body */
      }
      throw new ApiError(res.status, message);
    }
    if (raw) return new Uint8Array(await res.arrayBuffer());
    return res.status === 204 ? null : res.json();
  }

  function errorText(e) {
    if (e instanceof ApiError) {
      if (e.status === 0) return e.message;
      if (e.status === 401) return "הטוקן של GitHub לא תקף או שפג תוקפו. אפשר להחליף אותו בהגדרות ← אבטחה.";
      if (e.status === 403 && /rate limit/i.test(e.message)) return "יותר מדי בקשות ל-GitHub. נסו שוב בעוד כמה דקות.";
      if (e.status === 403 || e.status === 404) return "לטוקן אין הרשאה לעדכן את האתר. צריך הרשאת Contents: Read and write.";
      if (e.status === 409 || e.status === 422) return "האתר עודכן ממכשיר אחר באותו רגע. נסו לשמור שוב.";
      return `שגיאה מ-GitHub (${e.status}). נסו שוב בעוד רגע.`;
    }
    return e && e.message ? e.message : String(e);
  }

  const headSha = async () => (await gh(`git/ref/heads/${CONFIG.branch}`)).object.sha;
  const readData = async (ref) => normalize(await openData(S.key, await gh(`contents/${DATA_PATH}?ref=${ref}`, { raw: true })));

  // fill in what older data may lack, and give every colour a stable id (the store builds
  // item links and cart entries from it, so reordering colours never mixes them up)
  function normalize(d) {
    d.store ||= {};
    d.store.shipping ||= {};
    d.store.hours ||= [];
    d.tones ||= {};
    d.categories ||= [];
    d.deals ||= [];
    d.products ||= [];
    d.looks ||= [];
    for (const p of d.products) {
      p.sizes ||= [];
      p.colors ||= [];
      const used = new Set(p.colors.map((c) => c.id).filter(Boolean));
      p.colors.forEach((c, i) => {
        c.soldOut ||= [];
        if (!c.id) {
          let n = i + 1;
          while (used.has(n)) n++;
          c.id = n;
          used.add(n);
        }
      });
    }
    return d;
  }

  // One save = one commit on top of the newest version: re-read the data, apply the change,
  // commit data.bin with any new photos, and move the branch. If another device committed in
  // between, the branch update is refused and the whole step runs again on the newer data.
  let queue = Promise.resolve();
  function save(message, { mutate, files = [] } = {}) {
    const run = queue.then(() => commit(message, mutate, files));
    queue = run.catch(() => {});
    return run;
  }

  async function commit(message, mutate, files) {
    setSync("saving");
    try {
      const blob = async (bytes) =>
        (await gh("git/blobs", { method: "POST", body: { content: toB64(bytes), encoding: "base64" } })).sha;
      const fileEntries = [];
      for (const f of files) fileEntries.push({ path: f.path, mode: "100644", type: "blob", sha: await blob(f.bytes) });
      for (let attempt = 0; ; attempt++) {
        const head = await headSha();
        const baseTree = (await gh(`git/commits/${head}`)).tree.sha;
        const tree = [...fileEntries];
        let next = null;
        if (mutate) {
          next = await readData(head);
          mutate(next);
          tree.push({ path: DATA_PATH, mode: "100644", type: "blob", sha: await blob(await sealData(S.key, next)) });
        }
        const newTree = await gh("git/trees", { method: "POST", body: { base_tree: baseTree, tree } });
        const newCommit = await gh("git/commits", {
          method: "POST",
          body: { message, tree: newTree.sha, parents: [head] },
        });
        try {
          await gh(`git/refs/heads/${CONFIG.branch}`, { method: "PATCH", body: { sha: newCommit.sha, force: false } });
        } catch (e) {
          if ((e.status === 422 || e.status === 409) && attempt < 4) {
            await sleep(600 * (attempt + 1));
            continue;
          }
          throw e;
        }
        if (next) S.data = next;
        setSync("saved");
        return next;
      }
    } catch (e) {
      setSync("error");
      throw e;
    }
  }

  function filesFor(refs) {
    return [...new Set(refs)]
      .filter((r) => r && uploads.has(r))
      .map((r) => ({ ref: r, path: `${CONFIG.dir}/${r}`, bytes: uploads.get(r) }));
  }
  const forget = (files) => files.forEach((f) => uploads.delete(f.ref));

  // ---------- images ----------
  const imageCache = new Map(); // ref -> Promise<object URL>
  const IMAGE_TYPES = { webp: "image/webp", jpg: "image/jpeg", png: "image/png" };

  function imageUrl(ref) {
    if (!imageCache.has(ref)) {
      const p = (async () => {
        let bytes;
        const r = await fetch(SITE + ref).catch(() => null);
        if (r && r.ok) bytes = new Uint8Array(await r.arrayBuffer());
        // saved a moment ago from another device: not on the site yet, read it from the repo
        else bytes = await gh(`contents/${CONFIG.dir}/${ref}?ref=${CONFIG.branch}`, { raw: true });
        const plain = await unseal(S.key, bytes.subarray(0, 12), bytes.subarray(12));
        return URL.createObjectURL(new Blob([plain], { type: IMAGE_TYPES[/\.(\w+)\.bin$/.exec(ref)?.[1]] || "image/webp" }));
      })();
      p.catch(() => imageCache.delete(ref));
      imageCache.set(ref, p);
    }
    return imageCache.get(ref);
  }

  function hydrate(root) {
    for (const img of root.querySelectorAll("img[data-ref]")) {
      const ref = img.dataset.ref;
      imageUrl(ref).then(
        (url) => {
          if (img.dataset.ref !== ref) return;
          img.src = url;
          img.classList.add("ready");
        },
        () => {}
      );
    }
  }

  const imgTag = (ref) => (ref ? `<img data-ref="${esc(ref)}" alt="">` : "");
  const thumb = (ref, cls = "") => `<span class="thumb${cls ? " " + cls : ""}">${imgTag(ref)}</span>`;

  // resize on the device (a phone photo is several MB) and save as WebP, or JPEG where the
  // browser can't write WebP (Safari)
  async function processImage(file) {
    let src;
    try {
      src = await createImageBitmap(file, { imageOrientation: "from-image" });
    } catch {
      src = await new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = reject;
        img.src = URL.createObjectURL(file);
      });
    }
    const w0 = src.width || src.naturalWidth;
    const h0 = src.height || src.naturalHeight;
    const scale = Math.min(1, MAX_IMAGE / Math.max(w0, h0));
    const canvas = document.createElement("canvas");
    canvas.width = Math.round(w0 * scale);
    canvas.height = Math.round(h0 * scale);
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff"; // transparent PNGs get the white studio background
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.imageSmoothingQuality = "high";
    ctx.drawImage(src, 0, 0, canvas.width, canvas.height);
    const toBlob = (type, q) => new Promise((r) => canvas.toBlob(r, type, q));
    let blob = await toBlob("image/webp", 0.84);
    if (!blob || blob.type !== "image/webp") blob = await toBlob("image/jpeg", 0.86);
    if (!blob) throw new Error("image encode failed");
    const ext = blob.type === "image/webp" ? "webp" : "jpg";
    return { bytes: new Uint8Array(await blob.arrayBuffer()), ext, url: URL.createObjectURL(blob) };
  }

  async function uploadPhoto(file) {
    const img = await processImage(file);
    const { file: sealed, ref } = await sealImage(S.key, img.bytes, img.ext);
    uploads.set(ref, sealed);
    imageCache.set(ref, Promise.resolve(img.url));
    return ref;
  }

  // ---------- store helpers ----------
  const today = () => {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  };
  const isLive = (d) => !!d && d.active !== false && (!d.until || today() <= d.until);
  const fmtDate = (s) => {
    const [y, m, d] = s.split("-");
    return `${+d}.${+m}.${y}`;
  };
  const money = (n) => `${S.data.store.currency || "₪"}${Number(n || 0).toLocaleString("he-IL")}`;
  const category = (id) => S.data.categories.find((c) => c.id === id);
  // category names may end with an emoji ("קפוצ'ונים ❄️"); keep it out of sentences
  const plainName = (c) => (c ? c.name.replace(/\p{Extended_Pictographic}|️/gu, "").trim() : "");
  const studioClass = (catId) => (category(catId)?.studio ? "studio" : "");
  const itemId = (p, c) => (p.colors.length > 1 ? `${p.id}-${c.id}` : p.id);
  const itemRef = (p, c) => (p.colors.length > 1 ? `${p.id}:${c.name}` : p.id);
  const itemName = (p, c) => (p.colors.length > 1 && c ? `${p.name} ${c.name}` : p.name);
  const saleLive = (p) => !!p.sale && p.sale.price > 0 && p.sale.price < p.price && isLive(p.sale);
  const isOut = (p, c) => p.sizes.length > 0 && p.sizes.every((s) => c.soldOut.includes(s));
  const sizeRange = (sizes) => (sizes.length > 2 ? `${sizes[0]}–${sizes[sizes.length - 1]}` : sizes.join(", "));
  const categoryImage = (c) => c.image || S.data.products.find((p) => p.category === c.id)?.colors[0]?.image;
  const ROLES = {
    top: "עליון (חולצה / קפוצ'ון)",
    bottom: "תחתון (מכנס / ג'ינס)",
    set: "חליפה (עליון + תחתון)",
    shoes: "נעליים",
    other: "אחר (אביזרים)",
  };
  const ROLE_ORDER = { set: 0, top: 1, bottom: 2, shoes: 3 };
  const TONES = { dark: "כהה", light: "בהיר", earth: "אדמה (בז', חום)", denim: "ג'ינס (כחול)", mono: "שחור-לבן" };

  // a new colour gets its swatch and its tone (used by the automatic looks) from its name
  const COLOR_HINTS = [
    ["שחור", "#1f1f1f", "dark"],
    ["לבן", "#f3f1ec", "light"],
    ["שמנת", "#ece3d0", "light"],
    ["אפור", "#7d7d7d", "dark"],
    ["בז'", "#c9b79c", "earth"],
    ["חום", "#6b4a2f", "earth"],
    ["מוקה", "#6f5643", "earth"],
    ["קאמל", "#b08850", "earth"],
    ["חאקי", "#8b7d55", "earth"],
    ["זית", "#6b6b3f", "earth"],
    ["תכלת", "#8fb3d9", "denim"],
    ["נייבי", "#1f2a44", "dark"],
    ["כחול", "#2f4f7f", "denim"],
    ["ירוק", "#4f6b3f", "earth"],
    ["בורדו", "#6b1f2a", "dark"],
    ["אדום", "#b03030", null],
    ["ורוד", "#e8a8b8", "light"],
    ["צהוב", "#e8c547", "light"],
    ["כתום", "#e07b39", "earth"],
    ["סגול", "#6b4f8f", "dark"],
  ];
  function hexFor(name) {
    for (const p of S.data.products) for (const c of p.colors) if (c.name === name && c.hex) return c.hex;
    return COLOR_HINTS.find(([w]) => name.includes(w))?.[1] || null;
  }
  function guessTone(name) {
    if (!name) return null;
    if (S.data.tones[name]) return S.data.tones[name];
    if (/שחור/.test(name) && /לבן/.test(name)) return "mono";
    return COLOR_HINTS.find(([w]) => name.includes(w))?.[2] || null;
  }

  function resolveRef(d, ref) {
    const [pid, color] = ref.split(":");
    const p = d.products.find((x) => x.id === pid);
    if (!p) return null;
    const c = color ? p.colors.find((x) => x.name === color) : p.colors[0];
    return c ? { p, c } : null;
  }
  const roleOfRef = (d, ref) => {
    const it = resolveRef(d, ref);
    return it ? ROLE_ORDER[d.categories.find((c) => c.id === it.p.category)?.role] ?? 4 : 5;
  };
  // drop look items whose product or colour is gone, and looks left with fewer than 2 items
  const cleanLooks = (d) => {
    d.looks = d.looks.map((l) => l.filter((ref) => resolveRef(d, ref))).filter((l) => l.length > 1);
  };
  // a renamed colour keeps its looks
  function relinkLooks(d, before, after) {
    const names = new Map(after.colors.map((c) => [c.id, c.name]));
    const renamed = new Map(before.colors.map((c) => [c.name, names.get(c.id)]));
    d.looks = d.looks.map((look) =>
      look.map((ref) => {
        const [pid, color] = ref.split(":");
        if (pid !== before.id || color === undefined || !renamed.get(color)) return ref;
        return `${pid}:${renamed.get(color)}`;
      })
    );
    cleanLooks(d);
  }

  // ---------- UI basics ----------
  const view = $("#view");
  let toastTimer = 0;
  function toast(text, error) {
    const el = $("#toast");
    el.textContent = text;
    el.classList.toggle("error", !!error);
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), error ? 5000 : 2800);
  }

  let syncTimer = 0;
  let pending = 0;
  function setSync(state) {
    if (state === "saving") pending++;
    else pending = Math.max(0, pending - 1);
    const now = pending ? "saving" : state;
    const text = { saving: "שומר…", saved: "נשמר", error: "השמירה נכשלה" }[now];
    $$("[data-sync]").forEach((el) => {
      el.dataset.state = now;
      el.textContent = text;
    });
    $("#progress").hidden = !pending;
    clearTimeout(syncTimer);
    if (now === "saved") syncTimer = setTimeout(() => $$("[data-sync]").forEach((el) => (el.textContent = "")), 4000);
  }

  function confirmBox(text, { ok = "אישור", danger = false } = {}) {
    const dlg = $("#confirm");
    $("#confirmText").textContent = text;
    $("#confirmOk").textContent = ok;
    dlg.classList.toggle("danger", danger);
    dlg.returnValue = "";
    dlg.showModal();
    return new Promise((resolve) => dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true }));
  }

  function busyButton(btn, on) {
    btn.disabled = on;
    btn.classList.toggle("is-busy", on);
  }

  // drag rows by their handle to reorder a list (touch and mouse)
  function sortable(list, onDrop) {
    list.addEventListener("pointerdown", (e) => {
      const handle = e.target.closest(".drag");
      if (!handle || e.button > 0) return;
      const item = handle.closest("[data-id]");
      e.preventDefault();
      const before = $$(":scope > [data-id]", list).map((el) => el.dataset.id);
      const grab = e.clientY - item.getBoundingClientRect().top;
      let y = e.clientY;
      let raf = 0;
      handle.setPointerCapture?.(e.pointerId);
      item.classList.add("dragging");
      list.classList.add("sorting");
      const place = () => {
        item.style.transform = "";
        const center = y - grab + item.offsetHeight / 2;
        // the dragged row is never moved itself (that would drop the pointer); its neighbours are
        for (let k = 0; k < 50; k++) {
          const prev = item.previousElementSibling;
          const next = item.nextElementSibling;
          const mid = (el) => el.getBoundingClientRect().top + el.offsetHeight / 2;
          if (prev && center < mid(prev)) list.insertBefore(prev, item.nextElementSibling);
          else if (next && center > mid(next)) list.insertBefore(next, item);
          else break;
        }
        item.style.transform = `translateY(${y - grab - item.getBoundingClientRect().top}px)`;
      };
      const edge = () => {
        const bottom = innerHeight - (matchMedia("(min-width: 960px)").matches ? 0 : 70);
        const dy = y < 90 ? -10 : y > bottom - 60 ? 10 : 0;
        if (dy) {
          scrollBy(0, dy);
          place();
        }
        raf = requestAnimationFrame(edge);
      };
      raf = requestAnimationFrame(edge);
      const move = (ev) => {
        y = ev.clientY;
        place();
      };
      const end = () => {
        cancelAnimationFrame(raf);
        removeEventListener("pointermove", move);
        removeEventListener("pointerup", end);
        removeEventListener("pointercancel", end);
        item.classList.remove("dragging");
        list.classList.remove("sorting");
        item.style.transform = "";
        const after = $$(":scope > [data-id]", list).map((el) => el.dataset.id);
        if (after.join() !== before.join()) onDrop(after);
      };
      addEventListener("pointermove", move);
      addEventListener("pointerup", end);
      addEventListener("pointercancel", end);
    });
  }

  // ---------- views ----------
  const VIEWS = {
    products: renderProducts,
    deals: renderDeals,
    categories: renderCategories,
    looks: renderLooks,
    settings: renderSettings,
  };

  function show(name, focus) {
    if (!VIEWS[name]) name = "products";
    if (S.view === "settings" && name !== "settings" && settingsDirty()) {
      confirmBox("יש שינויים בהגדרות שלא נשמרו. לעזוב בלי לשמור?", { ok: "לעזוב", danger: true }).then((yes) => {
        if (yes) {
          SET = null;
          show(name, focus);
        }
      });
      return;
    }
    if (name !== "settings") SET = null;
    S.view = name;
    history.replaceState(history.state, "", "#" + name);
    $$("[data-view]").forEach((b) => b.setAttribute("aria-current", b.dataset.view === name ? "page" : "false"));
    renderView();
    scrollTo(0, 0);
    if (focus) view.focus({ preventScroll: true });
  }

  function renderView() {
    if (!S.data) return;
    VIEWS[S.view]();
    hydrate(view);
  }

  const pageHead = (title, count, action, label) => `
    <div class="page-head">
      <h1>${title}${count != null ? `<span class="sub">${count}</span>` : ""}</h1>
      ${action ? `<button class="btn btn-primary btn-head" type="button" data-action="${action}">${icon("plus")}${label}</button>` : ""}
    </div>`;
  const fab = (action, label) =>
    `<button class="btn btn-primary fab" type="button" data-action="${action}">${icon("plus")}${label}</button>`;

  // ----- products -----
  function productBadges(p) {
    const b = [];
    if (p.hidden) b.push(`<span class="badge">${icon("eye-off")}מוסתר</span>`);
    if (saleLive(p)) b.push(`<span class="badge badge-sale">מבצע</span>`);
    else if (p.sale && p.sale.price) b.push(`<span class="badge badge-warn">המבצע הסתיים</span>`);
    const out = p.colors.filter((c) => isOut(p, c)).length;
    const some = p.colors.some((c) => c.soldOut.some((s) => p.sizes.includes(s)));
    if (out && out === p.colors.length) b.push(`<span class="badge badge-warn">אזל</span>`);
    else if (some) b.push(`<span class="badge badge-warn">אזל חלקית</span>`);
    if (p.tag === "new") b.push(`<span class="badge badge-new">NEW</span>`);
    return b.join("");
  }

  function productRow(p) {
    const price = saleLive(p) ? `<s>${money(p.price)}</s><span class="now">${money(p.sale.price)}</span>` : money(p.price);
    const colors =
      p.colors.length > 1
        ? `<span class="dots">${p.colors.map((c) => `<i style="--c:${esc(c.hex)}"></i>`).join("")}</span>${p.colors.length} צבעים`
        : esc(p.colors[0]?.name || "");
    return `<li class="row${p.hidden ? " is-hidden" : ""}" data-id="${esc(p.id)}" data-action="edit-product">
      <button class="drag" type="button" aria-label="גרירה לשינוי הסדר">${icon("drag")}</button>
      ${thumb(p.colors[0]?.image, studioClass(p.category))}
      <div class="row-main">
        <span class="row-title">${esc(p.name)}</span>
        <span class="row-meta">${price}<span>·</span>${colors}${p.sizes.length ? `<span>·</span><span dir="ltr">${esc(sizeRange(p.sizes))}</span>` : ""}</span>
        ${productBadges(p) ? `<span class="row-meta">${productBadges(p)}</span>` : ""}
      </div>
      ${icon("chevron", "chev")}
    </li>`;
  }

  function renderProducts() {
    const d = S.data;
    const count = (id) => d.products.filter((p) => p.category === id).length;
    const chip = (id, name, n) =>
      `<button class="chip" type="button" data-action="filter" data-cat="${esc(id)}" aria-pressed="${S.filter === id}">${esc(name)}<span class="count">${n}</span></button>`;
    view.innerHTML = `
      ${pageHead("מוצרים", d.products.length, "new-product", "מוצר חדש")}
      <label class="search field">${icon("search")}<input type="search" id="productSearch" placeholder="חיפוש מוצר או צבע" value="${esc(S.query)}" aria-label="חיפוש מוצר"></label>
      <div class="chips scroll">${chip("all", "הכל", d.products.length)}${d.categories.map((c) => chip(c.id, c.name, count(c.id))).join("")}</div>
      <div id="productList"></div>
      ${fab("new-product", "מוצר חדש")}`;
    renderProductList();
  }

  function renderProductList() {
    const d = S.data;
    const q = S.query.trim().toLowerCase();
    const matches = (p) => !q || `${p.name} ${p.colors.map((c) => c.name).join(" ")}`.toLowerCase().includes(q);
    const known = new Set(d.categories.map((c) => c.id));
    const groups = d.categories
      .filter((c) => S.filter === "all" || c.id === S.filter)
      .map((c) => ({ c, items: d.products.filter((p) => p.category === c.id && matches(p)) }));
    const orphans = d.products.filter((p) => !known.has(p.category) && matches(p));
    if (orphans.length && S.filter === "all") groups.push({ c: { id: "", name: "בלי קטגוריה" }, items: orphans });
    const shown = groups.filter((g) => g.items.length || (!q && S.filter !== "all"));
    const list = $("#productList");
    list.className = q ? "is-searching" : "";
    list.innerHTML = shown.length
      ? shown
          .map(
            (g) => `<section class="section">
              <div class="section-head"><h2>${esc(g.c.name)}</h2><span class="muted">${g.items.length}</span></div>
              ${
                g.items.length
                  ? `<ul class="list card" data-sort-cat="${esc(g.c.id)}">${g.items.map(productRow).join("")}</ul>`
                  : `<div class="card empty">${icon("box")}<span>אין עדיין מוצרים בקטגוריה הזו</span></div>`
              }
            </section>`
          )
          .join("")
      : `<div class="card empty">${icon("search")}<span>לא נמצאו מוצרים${q ? ` עבור "${esc(S.query)}"` : ""}</span></div>`;
    $$("[data-sort-cat]", list).forEach((ul) => ul.dataset.sortCat && sortable(ul, (ids) => reorderProducts(ul.dataset.sortCat, ids)));
    hydrate(list);
  }

  async function reorderProducts(cat, ids) {
    try {
      await save("סדר מוצרים", {
        mutate: (d) => {
          const slots = [];
          d.products.forEach((p, i) => p.category === cat && slots.push(i));
          const byId = new Map(d.products.map((p) => [p.id, p]));
          const ordered = ids.map((id) => byId.get(id)).filter((p) => p && p.category === cat);
          const rest = slots.map((i) => d.products[i]).filter((p) => !ids.includes(p.id));
          [...ordered, ...rest].forEach((p, k) => (d.products[slots[k]] = p));
        },
      });
      toast("הסדר נשמר");
    } catch (e) {
      toast(errorText(e), true);
    }
    if (S.view === "products") renderProductList();
  }

  // ----- deals -----
  function dealTitle(d) {
    if (d.type === "bundle") return `${d.qty} ${plainName(category(d.category)) || "פריטים"} ב-${money(d.price)}`;
    return `${d.percent}% הנחה על ${d.scope === "all" ? "כל החנות" : plainName(category(d.scope))}`;
  }
  function statusBadge(x) {
    if (x.active === false) return `<span class="badge">כבוי</span>`;
    if (x.until && x.until < today()) return `<span class="badge badge-warn">הסתיים ב-${fmtDate(x.until)}</span>`;
    return `<span class="badge badge-ok badge-dot">${x.until ? `פעיל עד ${fmtDate(x.until)}` : "פעיל"}</span>`;
  }

  function renderDeals() {
    const d = S.data;
    const sales = d.products.filter((p) => p.sale && p.sale.price);
    view.innerHTML = `
      ${pageHead("מבצעים", null, "new-deal", "מבצע חדש")}
      <p class="page-note">מבצע פעיל מופיע מיד באתר: על המוצרים, בסל ובהודעת ההזמנה בוואטסאפ.</p>
      ${
        d.deals.length
          ? `<ul class="list card">${d.deals
              .map(
                (x) => `<li class="row" data-id="${esc(x.id)}" data-action="edit-deal">
                  <span class="deal-icon${isLive(x) ? "" : " off"}" dir="ltr">${x.type === "bundle" ? `${x.qty}+` : "%"}</span>
                  <div class="row-main">
                    <span class="row-title">${esc(dealTitle(x))}</span>
                    <span class="row-meta">${statusBadge(x)}<span>${x.type === "bundle" ? "מבצע כמות" : "אחוז הנחה"}</span></span>
                  </div>
                  <input type="checkbox" class="switch" data-action="toggle-deal" data-id="${esc(x.id)}" ${x.active !== false ? "checked" : ""} aria-label="מבצע פעיל">
                </li>`
              )
              .join("")}</ul>`
          : `<div class="card empty">${icon("tag")}<span>אין מבצעים עדיין</span><button class="btn btn-ghost btn-sm" type="button" data-action="new-deal">יצירת מבצע ראשון</button></div>`
      }
      <section class="section">
        <div class="section-head"><h2>מוצרים במחיר מבצע</h2><span class="muted">${sales.length}</span></div>
        ${
          sales.length
            ? `<ul class="list card">${sales
                .map(
                  (p) => `<li class="row" data-id="${esc(p.id)}" data-action="edit-product">
                    ${thumb(p.colors[0]?.image, studioClass(p.category))}
                    <div class="row-main">
                      <span class="row-title">${esc(p.name)}</span>
                      <span class="row-meta"><s>${money(p.price)}</s><span class="now">${money(p.sale.price)}</span>${statusBadge(p.sale)}</span>
                    </div>
                    ${icon("chevron", "chev")}
                  </li>`
                )
                .join("")}</ul>`
            : `<p class="inline-note">מחיר מבצע למוצר מסוים מגדירים בדף העריכה של המוצר.</p>`
        }
      </section>
      ${fab("new-deal", "מבצע חדש")}`;
  }

  async function toggleDeal(input) {
    const id = input.dataset.id;
    const on = input.checked;
    try {
      await save(`${on ? "הפעלת" : "כיבוי"} מבצע`, {
        mutate: (d) => {
          const x = d.deals.find((y) => y.id === id);
          if (!x) throw new Error("המבצע נמחק ממכשיר אחר");
          x.active = on;
        },
      });
      toast(on ? "המבצע הופעל" : "המבצע כובה");
    } catch (e) {
      toast(errorText(e), true);
    }
    if (S.view === "deals") renderView();
  }

  // ----- categories -----
  function renderCategories() {
    const d = S.data;
    view.innerHTML = `
      ${pageHead("קטגוריות", d.categories.length, "new-category", "קטגוריה חדשה")}
      <p class="page-note">הסדר כאן הוא הסדר באתר. גוררים מהידית כדי לשנות.</p>
      <ul class="list card" id="categoryList">${d.categories
        .map((c) => {
          const n = d.products.filter((p) => p.category === c.id).length;
          return `<li class="row" data-id="${esc(c.id)}" data-action="edit-category">
            <button class="drag" type="button" aria-label="גרירה לשינוי הסדר">${icon("drag")}</button>
            ${thumb(categoryImage(c), "round")}
            <div class="row-main">
              <span class="row-title">${esc(c.name)}</span>
              <span class="row-meta">${n} מוצרים<span>·</span>${esc((ROLES[c.role] || ROLES.other).split(" (")[0])}${c.studio ? "<span>·</span>רקע סטודיו" : ""}</span>
            </div>
            ${icon("chevron", "chev")}
          </li>`;
        })
        .join("")}</ul>
      ${fab("new-category", "קטגוריה חדשה")}`;
    sortable($("#categoryList"), async (ids) => {
      try {
        await save("סדר קטגוריות", {
          mutate: (dd) => {
            const pos = (c) => {
              const i = ids.indexOf(c.id);
              return i < 0 ? ids.length : i;
            };
            dd.categories.sort((a, b) => pos(a) - pos(b));
          },
        });
        toast("הסדר נשמר");
      } catch (e) {
        toast(errorText(e), true);
      }
      if (S.view === "categories") renderView();
    });
  }

  // ----- looks -----
  function lookCard(look, i) {
    const d = S.data;
    const items = [...look].sort((a, b) => roleOfRef(d, a) - roleOfRef(d, b)).map((ref) => resolveRef(d, ref));
    const missing = items.some((it) => !it);
    const hidden = items.some((it) => it && it.p.hidden);
    return `<button class="look-card" type="button" data-action="edit-look" data-index="${i}">
      <span class="look-thumbs" style="--n:${items.length}">${items
        .map((it) => thumb(it?.c.image, it ? studioClass(it.p.category) : ""))
        .join("")}</span>
      <span class="look-names">${items.map((it) => (it ? esc(itemName(it.p, it.c)) : "פריט שנמחק")).join(" · ")}</span>
      ${missing || hidden ? `<span class="row-meta">${missing ? `<span class="badge badge-warn">יש פריט שנמחק</span>` : ""}${hidden ? `<span class="badge">יש פריט מוסתר</span>` : ""}</span>` : ""}
    </button>`;
  }

  function renderLooks() {
    const d = S.data;
    const q = S.lookQuery.trim().toLowerCase();
    const shown = d.looks
      .map((look, i) => ({ look, i }))
      .filter(
        ({ look }) =>
          !q ||
          look.some((ref) => {
            const it = resolveRef(d, ref);
            return it && itemName(it.p, it.c).toLowerCase().includes(q);
          })
      );
    view.innerHTML = `
      ${pageHead("לוקים", d.looks.length, "new-look", "לוק חדש")}
      <p class="page-note">לוק מוצג בדף של כל פריט שנמצא בו, תחת "השלם את הלוק". מוצר בלי לוק מקבל הצעה אוטומטית לפי צבעים.</p>
      <label class="search field">${icon("search")}<input type="search" id="lookSearch" placeholder="חיפוש לוק לפי מוצר" value="${esc(S.lookQuery)}" aria-label="חיפוש לוק"></label>
      ${
        shown.length
          ? `<div class="look-grid">${shown.map(({ look, i }) => lookCard(look, i)).join("")}</div>`
          : `<div class="card empty">${icon("layers")}<span>${q ? "אין לוקים עם המוצר הזה" : "אין לוקים עדיין"}</span></div>`
      }
      ${fab("new-look", "לוק חדש")}`;
  }

  // ----- settings -----
  let SET = null; // settings being edited: { draft, snapshot }
  const settingsDirty = () => !!SET && JSON.stringify(SET.draft) !== SET.snapshot;

  function renderSettings() {
    if (!SET) {
      const draft = clone(S.data.store);
      SET = { draft, snapshot: JSON.stringify(draft) };
    }
    const s = SET.draft;
    const field = (label, key, attrs = "", hint = "") => `<label class="field">
        <span class="field-label">${label}</span>
        <input data-sbind="${key}" value="${esc(getPath(s, key))}" ${attrs}>
        ${hint ? `<span class="field-hint">${hint}</span>` : ""}
      </label>`;
    view.innerHTML = `
      ${pageHead("הגדרות")}
      <div class="card card-pad stack">
        <h3 class="card-title">פרטי החנות</h3>
        <div class="row-2 stack-sm">${field("שם החנות", "name")}${field("שורת תיאור", "tagline")}</div>
        <div class="row-2 stack-sm">
          ${field("וואטסאפ להזמנות", "whatsapp", 'dir="ltr" inputmode="numeric"', "בפורמט בינלאומי: 972 ואחריו המספר בלי 0")}
          ${field("טלפון", "phone", 'dir="ltr" inputmode="tel"')}
        </div>
        <div class="row-2 stack-sm">${field("כתובת", "address")}${field("אינסטגרם", "instagram", 'dir="ltr"', "שם המשתמש בלבד, בלי @")}</div>
      </div>

      <div class="card card-pad">
        <h3 class="card-title">שעות פתיחה</h3>
        <div class="stack" style="gap:8px">${s.hours
          .map(
            (h, i) => `<div class="hours-row">
              <input class="input" data-sbind="hours.${i}.days" value="${esc(h.days)}" placeholder="ימים, למשל א'–ה'" aria-label="ימים">
              <input class="input" data-sbind="hours.${i}.time" value="${esc(h.time)}" placeholder="10:00–20:00" dir="ltr" aria-label="שעות">
              <button class="icon-btn" type="button" data-action="remove-hours" data-index="${i}" aria-label="מחיקת שורה">${icon("trash")}</button>
            </div>`
          )
          .join("")}</div>
        <button class="add-tile" type="button" data-action="add-hours" style="margin-top:12px;width:100%">${icon("plus")}הוספת שורה</button>
      </div>

      <div class="card card-pad stack">
        <h3 class="card-title">משלוחים</h3>
        <div class="row-2">
          <label class="field"><span class="field-label">מחיר משלוח</span><span class="prefix-input"><input data-sbind="shipping.price" data-num value="${esc(s.shipping.price ?? 0)}" inputmode="numeric"><span>₪</span></span></label>
          <label class="field"><span class="field-label">משלוח חינם מעל</span><span class="prefix-input"><input data-sbind="shipping.freeAbove" data-num value="${esc(s.shipping.freeAbove || "")}" inputmode="numeric" placeholder="ללא"><span>₪</span></span></label>
        </div>
        ${field("זמן אספקה", "shipping.eta")}
        <label class="switch-row"><span class="switch-text"><b>איסוף עצמי מהחנות</b><small>אפשרות לאסוף את ההזמנה במקום משלוח</small></span><input type="checkbox" class="switch" data-sbind="shipping.pickup" ${s.shipping.pickup ? "checked" : ""}></label>
      </div>

      <div class="card card-pad">
        <h3 class="card-title">תצוגה</h3>
        <label class="switch-row"><span class="switch-text"><b>פס "אתר לדוגמה"</b><small>הפס בראש האתר. מכבים כשהאתר עולה לאוויר</small></span><input type="checkbox" class="switch" data-sbind="demoMode" ${s.demoMode ? "checked" : ""}></label>
      </div>

      <div class="settings-actions" id="settingsBar" hidden>
        <span>יש שינויים שלא נשמרו</span>
        <button class="btn btn-sm btn-ghost" type="button" data-action="reset-settings" style="color:var(--ink)">ביטול</button>
        <button class="btn btn-sm btn-gold" type="button" data-action="save-settings">שמירה</button>
      </div>

      <div class="card card-pad stack" style="margin-top:28px">
        <h3 class="card-title">אבטחה<small>הסיסמה והטוקן נשמרים מוצפנים. משנים פה אם צריך</small></h3>
        <form class="stack" id="passwordForm" onsubmit="return false">
          <div class="row-2">
            <label class="field"><span class="field-label">סיסמת ניהול חדשה</span><input type="password" name="password" autocomplete="new-password" minlength="8"></label>
            <label class="field"><span class="field-label">שוב</span><input type="password" name="password2" autocomplete="new-password"></label>
          </div>
          <button class="btn btn-ghost" type="submit" style="justify-self:start">שינוי סיסמה</button>
        </form>
        <hr style="border:0;border-top:1px solid var(--line);margin:4px 0">
        <form class="stack" id="tokenForm" onsubmit="return false">
          <div class="row-2 stack-sm">
            <label class="field"><span class="field-label">טוקן GitHub חדש</span><input name="token" dir="ltr" spellcheck="false" autocapitalize="off" placeholder="github_pat_…"></label>
            <label class="field"><span class="field-label">סיסמת הניהול</span><input type="password" name="password" autocomplete="current-password"></label>
          </div>
          <button class="btn btn-ghost" type="submit" style="justify-self:start">החלפת טוקן</button>
        </form>
      </div>

      <button class="btn btn-ghost btn-block" type="button" data-action="logout" style="margin-top:18px">${icon("logout")}התנתקות מהמכשיר הזה</button>`;
    updateSettingsBar();
  }

  function updateSettingsBar() {
    const bar = $("#settingsBar");
    if (bar) bar.hidden = !settingsDirty();
  }

  async function saveSettings(btn) {
    const s = SET.draft;
    s.whatsapp = String(s.whatsapp || "").replace(/\D/g, "");
    s.instagram = String(s.instagram || "").replace(/^@/, "").trim();
    s.hours = s.hours.filter((h) => h.days.trim() || h.time.trim());
    if (s.whatsapp && !/^\d{10,15}$/.test(s.whatsapp)) return toast("מספר הוואטסאפ צריך להיות בפורמט בינלאומי, למשל 972545861678", true);
    if (s.whatsapp.startsWith("0")) return toast("מספר הוואטסאפ מתחיל ב-972 ולא ב-0", true);
    busyButton(btn, true);
    try {
      const draft = clone(s);
      await save("הגדרות החנות", { mutate: (d) => Object.assign(d.store, draft) });
      SET = null;
      toast("ההגדרות נשמרו. יופיעו באתר תוך כדקה");
      renderView();
    } catch (e) {
      busyButton(btn, false);
      toast(errorText(e), true);
    }
  }

  // ---------- editor window ----------
  const editor = $("#editor");
  const editorBody = $("#editorBody");

  function openEditor(cfg) {
    E = cfg;
    E.snapshot = JSON.stringify(E.draft);
    $("#editorTitle").textContent = E.title;
    $("#editorExtra").innerHTML = E.extra || "";
    $("#editorDelete").hidden = !E.remove;
    $("#editorError").textContent = "";
    busyButton($("#editorSave"), false);
    renderEditor();
    editorBody.scrollTop = 0;
    editor.showModal();
    history.pushState({ editor: true }, "", location.hash);
  }

  function renderEditor() {
    const top = editorBody.scrollTop;
    editorBody.innerHTML = E.render();
    hydrate(editorBody);
    E.live?.();
    editorBody.scrollTop = top;
  }

  const editorDirty = () => !!E && JSON.stringify(E.draft) !== E.snapshot;

  let asking = false;
  async function requestClose() {
    if (!E || asking) return;
    if (editorDirty()) {
      asking = true;
      const leave = await confirmBox("לצאת בלי לשמור את השינויים?", { ok: "יציאה בלי שמירה", danger: true });
      asking = false;
      if (!leave) return;
    }
    closeEditor();
  }

  function closeEditor() {
    E = null;
    uploads.clear(); // photos of a window closed without saving
    if (picker.open) picker.close();
    if (editor.open) editor.close();
    if (history.state && history.state.editor) history.back();
  }

  async function submitEditor() {
    if (!E) return;
    const btn = $("#editorSave");
    if (btn.disabled) return;
    const error = E.validate();
    $("#editorError").textContent = error || "";
    if (error) return;
    busyButton(btn, true);
    try {
      const message = await E.save();
      closeEditor();
      toast(message || "נשמר. יופיע באתר תוך כדקה");
      renderView();
    } catch (e) {
      $("#editorError").textContent = errorText(e);
      busyButton(btn, false);
    }
  }

  async function deleteFromEditor() {
    if (!E || !E.remove) return;
    const ok = await confirmBox(E.removeText || "למחוק?", { ok: "מחיקה", danger: true });
    if (!ok) return;
    const btn = $("#editorDelete");
    busyButton(btn, true);
    try {
      const message = await E.remove();
      closeEditor();
      toast(message || "נמחק");
      renderView();
    } catch (e) {
      $("#editorError").textContent = errorText(e);
    }
    busyButton(btn, false);
  }

  function getPath(obj, path) {
    return path.split(".").reduce((o, k) => (o == null ? o : o[k]), obj) ?? "";
  }
  function setPath(obj, path, value) {
    const keys = path.split(".");
    const last = keys.pop();
    const target = keys.reduce((o, k) => (o[k] ??= {}), obj);
    target[last] = value;
  }
  function inputValue(el) {
    if (el.type === "checkbox") return el.dataset.invert != null ? !el.checked : el.checked;
    if (el.dataset.num != null) {
      const n = parseInt(String(el.value).replace(/[^\d]/g, ""), 10);
      return Number.isFinite(n) ? n : null;
    }
    return el.value;
  }

  // ----- product editor -----
  const SIZE_PRESETS = [
    ["XS–XXL", ["XS", "S", "M", "L", "XL", "XXL"]],
    ["S–XXL", ["S", "M", "L", "XL", "XXL"]],
    ["28–38", ["28", "29", "30", "31", "32", "33", "34", "36", "38"]],
    ["נעליים 40–45", ["40", "41", "42", "43", "44", "45"]],
    ["מידה אחת", ["One Size"]],
  ];

  const newColor = (d) => ({
    id: Math.max(0, ...d.colors.map((c) => c.id || 0)) + 1,
    name: "",
    hex: "#cccccc",
    image: null,
    soldOut: [],
    _tone: "",
  });

  function productEditor(p) {
    const isNew = !p;
    if (isNew) {
      const cat = S.filter !== "all" && category(S.filter) ? S.filter : S.data.categories[0]?.id || "";
      const like = S.data.products.find((x) => x.category === cat);
      p = {
        id: newId("p"),
        name: "",
        category: cat,
        price: like?.price || null,
        sizes: like ? [...like.sizes] : [],
        tag: "new",
        colors: [],
        description: "",
        print: 0,
        style: null,
        hidden: false,
        sale: null,
      };
      p.colors.push(newColor(p));
    }
    const draft = clone(p);
    draft.colors.forEach((c) => {
      c._tone = S.data.tones[c.name] || "";
      c._hexSet = !!c.name; // an existing colour keeps its swatch when renamed
    });
    const first = draft.colors[0];
    return {
      kind: "product",
      draft,
      isNew,
      original: isNew ? null : clone(p),
      title: isNew ? "מוצר חדש" : "עריכת מוצר",
      extra: isNew
        ? ""
        : `<a href="${SITE}#p=${encodeURIComponent(itemId(p, first))}" target="_blank" rel="noopener">באתר ↗</a>`,
      render: productForm,
      live: productLive,
      validate: validateProduct,
      save: saveProduct,
      remove: isNew ? null : removeProduct,
      removeText: `למחוק את "${p.name}"?\nהמוצר יוסר מהאתר ומכל הלוקים.`,
    };
  }

  function productForm() {
    const d = E.draft;
    const studio = studioClass(d.category);
    const knownNames = [...new Set([...Object.keys(S.data.tones), ...S.data.products.flatMap((p) => p.colors.map((c) => c.name))])];
    const colorCard = (c, i) => `<div class="color-card" data-ci="${i}">
        <label class="color-photo${c.image ? " has-img" : ""}${studio ? " studio" : ""}">
          ${
            c.image
              ? `${imgTag(c.image)}<span class="photo-change">${icon("camera")}החלפה</span>`
              : `<span class="photo-cta">${icon("camera")}<span>הוספת תמונה</span></span>`
          }
          <input type="file" accept="image/*" data-photo="${i}" aria-label="תמונה לצבע ${i + 1}">
        </label>
        <div class="color-fields">
          <div class="color-head">
            <span class="mini-label">${d.colors.length > 1 ? `צבע ${i + 1}` : "צבע"}</span>
            <span class="color-tools">
              ${i > 0 ? `<button class="icon-btn" type="button" data-action="color-up" data-ci="${i}" aria-label="להזיז למעלה">${icon("up")}</button>` : ""}
              ${i < d.colors.length - 1 ? `<button class="icon-btn" type="button" data-action="color-down" data-ci="${i}" aria-label="להזיז למטה">${icon("down")}</button>` : ""}
              ${d.colors.length > 1 ? `<button class="icon-btn danger" type="button" data-action="color-remove" data-ci="${i}" aria-label="מחיקת הצבע">${icon("trash")}</button>` : ""}
            </span>
          </div>
          <div class="color-line">
            <label class="field"><span class="field-label">שם הצבע</span><input data-bind="colors.${i}.name" data-color-name="${i}" value="${esc(c.name)}" list="colorNames" maxlength="30" placeholder="למשל שחור"></label>
            <label class="swatch" title="גוון הצבע (הנקודה בכרטיס)"><input type="color" data-bind="colors.${i}.hex" value="${esc(c.hex || "#cccccc")}" aria-label="גוון הצבע"></label>
          </div>
          ${
            d.sizes.length
              ? `<div class="field"><span class="mini-label">אזל במידות (הקישו על מידה)</span><div class="chips out-chips">${d.sizes
                  .map((s) => {
                    const out = c.soldOut.includes(s);
                    return `<button class="chip size-chip${out ? " is-out" : ""}" type="button" data-action="toggle-out" data-ci="${i}" data-size="${esc(s)}" aria-pressed="${out}">${esc(s)}</button>`;
                  })
                  .join("")}</div></div>`
              : ""
          }
        </div>
      </div>`;
    const sale = d.sale;
    return `
      <div class="card card-pad stack">
        <label class="field"><span class="field-label">שם המוצר</span><input data-bind="name" value="${esc(d.name)}" maxlength="80" placeholder="למשל קפוצ'ון Building Dreams"></label>
        <div class="row-2">
          <label class="field"><span class="field-label">קטגוריה</span><select data-bind="category" data-rerender>${S.data.categories
            .map((c) => `<option value="${esc(c.id)}"${c.id === d.category ? " selected" : ""}>${esc(c.name)}</option>`)
            .join("")}</select></label>
          <label class="field"><span class="field-label">מחיר</span><span class="prefix-input"><input data-bind="price" data-num value="${esc(d.price ?? "")}" inputmode="numeric" placeholder="0"><span>₪</span></span></label>
        </div>
      </div>

      <div class="card card-pad">
        <h3 class="card-title">צבעים ותמונות<small>כל צבע מופיע באתר כפריט נפרד, עם דף משלו</small></h3>
        <div class="colors">${d.colors.map(colorCard).join("")}</div>
        <button class="add-tile" type="button" data-action="add-color" style="width:100%;margin-top:12px">${icon("plus")}הוספת צבע</button>
        <datalist id="colorNames">${knownNames.map((n) => `<option value="${esc(n)}">`).join("")}</datalist>
      </div>

      <div class="card card-pad">
        <h3 class="card-title">מידות</h3>
        <div class="chips">${
          d.sizes.length
            ? d.sizes
                .map(
                  (s) =>
                    `<span class="chip size-chip">${esc(s)}<button class="chip-x" type="button" data-action="remove-size" data-size="${esc(s)}" aria-label="הסרת מידה ${esc(s)}">✕</button></span>`
                )
                .join("")
            : `<span class="field-hint">אין מידות עדיין. בחרו סט מוכן או הוסיפו מידה</span>`
        }</div>
        <div class="size-tools"><span class="mini-label">סט מוכן:</span>${SIZE_PRESETS.map(
          ([label], i) => `<button class="chip preset" type="button" data-action="size-preset" data-index="${i}">${label}</button>`
        ).join("")}</div>
        <div class="size-add"><input class="input" id="sizeInput" placeholder="מידה נוספת, למשל 3XL" maxlength="12" aria-label="מידה נוספת"><button class="btn btn-ghost btn-sm" type="button" data-action="add-size">הוספה</button></div>
      </div>

      <div class="card card-pad stack">
        <label class="field"><span class="field-label">תיאור</span><textarea data-bind="description" maxlength="600" placeholder="חומר, גזרה, מה מיוחד בפריט">${esc(d.description)}</textarea></label>
      </div>

      <div class="card card-pad">
        <label class="switch-row"><span class="switch-text"><b>מחיר מבצע</b><small>מחיר מוזל למוצר הזה, עם תאריך סיום אם רוצים</small></span><input type="checkbox" class="switch" data-action="toggle-sale" ${sale ? "checked" : ""}></label>
        ${
          sale
            ? `<div class="row-2" style="margin-top:6px">
                <label class="field"><span class="field-label">מחיר במבצע</span><span class="prefix-input"><input data-bind="sale.price" data-num value="${esc(sale.price ?? "")}" inputmode="numeric"><span>₪</span></span></label>
                <label class="field"><span class="field-label">עד תאריך (לא חובה)</span><input type="date" data-bind="sale.until" value="${esc(sale.until || "")}" min="${today()}"></label>
              </div>
              <p class="discount-note" id="discountNote" style="margin-top:8px"></p>`
            : ""
        }
      </div>

      <div class="card card-pad">
        <label class="switch-row"><span class="switch-text"><b>מוצג באתר</b><small>כבוי = המוצר מוסתר מהלקוחות ונשמר כאן</small></span><input type="checkbox" class="switch" data-bind="hidden" data-invert ${d.hidden ? "" : "checked"}></label>
        <label class="switch-row"><span class="switch-text"><b>תגית NEW</b><small>מסמן את המוצר כחדש בכרטיס</small></span><input type="checkbox" class="switch" data-action="toggle-new" ${d.tag === "new" ? "checked" : ""}></label>
      </div>

      <details class="card"${E.advancedOpen ? " open" : ""} id="advanced">
        <summary><span>התאמת לוקים אוטומטית<small>עוזר להציע לוק למוצר שאין לו לוק שבחרתם</small></span>${icon("down")}</summary>
        <div class="stack">
          <div class="row-2">
            <label class="field"><span class="field-label">הדפס</span><select data-bind="print" data-num>
              ${[["0", "חלק, בלי הדפס"], ["1", "הדפס או לוגו"], ["2", "הדפס על כל הבגד"]]
                .map(([v, l]) => `<option value="${v}"${String(d.print || 0) === v ? " selected" : ""}>${l}</option>`)
                .join("")}
            </select></label>
            <label class="field"><span class="field-label">סגנון</span><select data-bind="style">
              <option value=""${d.style ? "" : " selected"}>יומיומי</option>
              <option value="smart"${d.style === "smart" ? " selected" : ""}>אלגנט</option>
            </select></label>
          </div>
          ${d.colors
            .map(
              (c, i) => `<label class="field"><span class="field-label">גוון: ${esc(c.name || `צבע ${i + 1}`)}</span><select data-bind="colors.${i}._tone">
                <option value="">אוטומטי לפי השם</option>
                ${Object.entries(TONES)
                  .map(([v, l]) => `<option value="${v}"${c._tone === v ? " selected" : ""}>${l}</option>`)
                  .join("")}
              </select></label>`
            )
            .join("")}
        </div>
      </details>`;
  }

  function productLive() {
    const note = $("#discountNote");
    if (!note) return;
    const { price, sale } = E.draft;
    note.textContent =
      price > 0 && sale?.price > 0 && sale.price < price ? `${Math.round((1 - sale.price / price) * 100)}% הנחה · במקום ${money(price)}` : "";
  }

  function validateProduct() {
    const d = E.draft;
    if (!d.name.trim()) return "חסר שם למוצר";
    if (!category(d.category)) return "בחרו קטגוריה";
    if (!(d.price > 0)) return "חסר מחיר";
    if (!d.colors.length) return "צריך לפחות צבע אחד";
    if (d.colors.some((c) => !c.image)) return "לכל צבע צריך תמונה";
    if (d.colors.length > 1 && d.colors.some((c) => !c.name.trim())) return "לכל צבע צריך שם";
    if (d.colors.some((c) => c.name.includes(":"))) return 'שם צבע לא יכול לכלול ":"';
    const names = d.colors.map((c) => c.name.trim());
    if (new Set(names).size !== names.length) return "יש שני צבעים עם אותו שם";
    if (!d.sizes.length) return "צריך לפחות מידה אחת";
    if (d.sale) {
      if (!(d.sale.price > 0)) return "חסר מחיר מבצע";
      if (d.sale.price >= d.price) return "מחיר המבצע צריך להיות נמוך מהמחיר הרגיל";
    }
    return null;
  }

  async function saveProduct() {
    const draft = clone(E.draft);
    draft.name = draft.name.trim();
    draft.description = (draft.description || "").trim();
    draft.style = draft.style || null;
    if (draft.sale) draft.sale = { price: draft.sale.price, until: draft.sale.until || null };
    const tones = {};
    const guessed = {};
    for (const c of draft.colors) {
      c.name = c.name.trim();
      c.soldOut = c.soldOut.filter((s) => draft.sizes.includes(s));
      if (c._tone) tones[c.name] = c._tone;
      else if (guessTone(c.name)) guessed[c.name] = guessTone(c.name);
      delete c._tone;
      delete c._hexSet;
    }
    const files = filesFor(draft.colors.map((c) => c.image));
    const isNew = E.isNew;
    await save(`${isNew ? "מוצר חדש" : "עדכון מוצר"}: ${draft.name}`, {
      files,
      mutate: (d) => {
        const i = d.products.findIndex((p) => p.id === draft.id);
        if (i >= 0) {
          const before = d.products[i];
          d.products[i] = draft;
          relinkLooks(d, before, draft);
        } else {
          // new products open their category
          const at = d.products.findIndex((p) => p.category === draft.category);
          d.products.splice(at < 0 ? d.products.length : at, 0, draft);
        }
        for (const [name, t] of Object.entries(guessed)) d.tones[name] ||= t;
        Object.assign(d.tones, tones);
      },
    });
    forget(files);
    return isNew ? "המוצר נוסף. יופיע באתר תוך כדקה" : "המוצר נשמר. יופיע באתר תוך כדקה";
  }

  async function removeProduct() {
    const id = E.draft.id;
    await save(`מחיקת מוצר: ${E.draft.name}`, {
      mutate: (d) => {
        d.products = d.products.filter((p) => p.id !== id);
        cleanLooks(d);
      },
    });
    return "המוצר נמחק";
  }

  // ----- deal editor -----
  function dealEditor(x) {
    const isNew = !x;
    const firstCat = S.data.categories[0]?.id || "";
    const draft = x
      ? { qty: 2, price: null, category: firstCat, percent: null, scope: "all", ...clone(x) }
      : { id: newId("deal-"), type: "bundle", category: firstCat, qty: 2, price: null, percent: null, scope: "all", active: true, until: null };
    return {
      kind: "deal",
      draft,
      isNew,
      title: isNew ? "מבצע חדש" : "עריכת מבצע",
      render: dealForm,
      live: dealLive,
      validate: validateDeal,
      save: saveDeal,
      remove: isNew ? null : removeDeal,
      removeText: "למחוק את המבצע?",
    };
  }

  function dealForm() {
    const d = E.draft;
    const cats = S.data.categories;
    const opt = (v, l, sel) => `<option value="${esc(v)}"${v === sel ? " selected" : ""}>${esc(l)}</option>`;
    return `
      <div class="card card-pad stack">
        <div class="segmented" role="radiogroup" aria-label="סוג המבצע">
          <label><input type="radio" name="dealType" value="bundle" data-bind="type" data-rerender ${d.type === "bundle" ? "checked" : ""}><span>כמות במחיר</span></label>
          <label><input type="radio" name="dealType" value="percent" data-bind="type" data-rerender ${d.type === "percent" ? "checked" : ""}><span>אחוז הנחה</span></label>
        </div>
        ${
          d.type === "bundle"
            ? `<label class="field"><span class="field-label">קטגוריה</span><select data-bind="category">${cats.map((c) => opt(c.id, c.name, d.category)).join("")}</select>
                 <span class="field-hint">אפשר לשלב דגמים וצבעים שונים מאותה קטגוריה</span></label>
               <div class="row-2">
                 <label class="field"><span class="field-label">כמות</span><input data-bind="qty" data-num value="${esc(d.qty ?? "")}" inputmode="numeric"></label>
                 <label class="field"><span class="field-label">מחיר לכולם יחד</span><span class="prefix-input"><input data-bind="price" data-num value="${esc(d.price ?? "")}" inputmode="numeric"><span>₪</span></span></label>
               </div>`
            : `<label class="field"><span class="field-label">על מה</span><select data-bind="scope">${opt("all", "כל החנות", d.scope)}${cats
                .map((c) => opt(c.id, c.name, d.scope))
                .join("")}</select></label>
               <label class="field"><span class="field-label">אחוז הנחה</span><span class="prefix-input"><input data-bind="percent" data-num value="${esc(d.percent ?? "")}" inputmode="numeric" placeholder="20"><span>%</span></span>
                 <span class="field-hint">מוצר עם מחיר מבצע משלו שומר על המחיר שלו</span></label>`
        }
        <p class="inline-note" id="dealPreview"></p>
      </div>

      <div class="card card-pad">
        <label class="switch-row"><span class="switch-text"><b>פעיל</b><small>אפשר לכבות ולהדליק בלי למחוק</small></span><input type="checkbox" class="switch" data-bind="active" ${d.active !== false ? "checked" : ""}></label>
        <label class="field" style="margin-top:8px"><span class="field-label">תאריך סיום (לא חובה)</span><input type="date" data-bind="until" value="${esc(d.until || "")}">
          <span class="field-hint">המבצע מסתיים אוטומטית בסוף היום הזה</span></label>
      </div>`;
  }

  function dealLive() {
    const el = $("#dealPreview");
    if (!el) return;
    const d = E.draft;
    const priceOf = (cat) => S.data.products.find((p) => !p.hidden && (cat === "all" || p.category === cat))?.price;
    if (d.type === "bundle") {
      const unit = priceOf(d.category);
      el.textContent =
        d.qty > 1 && d.price > 0
          ? `באתר: "${d.qty} ב-${money(d.price)}"${unit ? ` · במקום ${money(unit * d.qty)} (${Math.round((1 - d.price / (unit * d.qty)) * 100)}% הנחה)` : ""}`
          : "לדוגמה: 2 ג'ינסים ב-299";
    } else {
      const unit = priceOf(d.scope);
      el.textContent =
        d.percent > 0 && unit ? `לדוגמה: פריט של ${money(unit)} יימכר ב-${money(Math.round((unit * (100 - d.percent)) / 100))}` : "לדוגמה: 20% הנחה על נעליים";
    }
  }

  function validateDeal() {
    const d = E.draft;
    if (d.type === "bundle") {
      if (!category(d.category)) return "בחרו קטגוריה";
      if (!(d.qty >= 2)) return "כמות של 2 לפחות";
      if (!(d.price > 0)) return "חסר מחיר";
      const clash = S.data.deals.find((x) => x.id !== d.id && x.type === "bundle" && x.category === d.category && isLive(x));
      if (clash && isLive(d)) return `כבר יש מבצע כמות פעיל על ${plainName(category(d.category))}. כבו אותו קודם.`;
    } else if (!(d.percent >= 1 && d.percent <= 90)) return "אחוז הנחה בין 1 ל-90";
    if (d.until && d.until < today() && d.active !== false) return "תאריך הסיום כבר עבר";
    return null;
  }

  async function saveDeal() {
    const d = E.draft;
    const deal =
      d.type === "bundle"
        ? { id: d.id, type: "bundle", category: d.category, qty: d.qty, price: d.price, active: d.active !== false, until: d.until || null }
        : { id: d.id, type: "percent", scope: d.scope, percent: d.percent, active: d.active !== false, until: d.until || null };
    await save(`מבצע: ${dealTitle(deal)}`, {
      mutate: (data) => {
        const i = data.deals.findIndex((x) => x.id === deal.id);
        if (i >= 0) data.deals[i] = deal;
        else data.deals.push(deal);
      },
    });
    return E.isNew ? "המבצע נוצר. יופיע באתר תוך כדקה" : "המבצע נשמר";
  }

  async function removeDeal() {
    const id = E.draft.id;
    await save("מחיקת מבצע", { mutate: (d) => (d.deals = d.deals.filter((x) => x.id !== id)) });
    return "המבצע נמחק";
  }

  // ----- category editor -----
  function categoryEditor(c) {
    const isNew = !c;
    const draft = c ? clone(c) : { id: newId("c"), name: "", role: "top", image: null, studio: false };
    const n = S.data.products.filter((p) => p.category === draft.id).length;
    return {
      kind: "category",
      draft,
      isNew,
      title: isNew ? "קטגוריה חדשה" : "עריכת קטגוריה",
      render: categoryForm,
      validate: () => (draft.name.trim() ? null : "חסר שם לקטגוריה"),
      save: saveCategory,
      remove: isNew ? null : removeCategory,
      removeText: n ? "" : `למחוק את הקטגוריה "${draft.name}"?`,
      count: n,
    };
  }

  function categoryForm() {
    const d = E.draft;
    const fallback = categoryImage(d);
    return `
      <div class="card card-pad stack">
        <label class="field"><span class="field-label">שם הקטגוריה</span><input data-bind="name" value="${esc(d.name)}" maxlength="40" placeholder="למשל מכנסי ג'וגר"></label>
        <label class="field"><span class="field-label">סוג הפריטים</span><select data-bind="role">${Object.entries(ROLES)
          .map(([v, l]) => `<option value="${v}"${(d.role || "other") === v ? " selected" : ""}>${l}</option>`)
          .join("")}</select><span class="field-hint">עוזר להרכיב לוקים: עליון + תחתון + נעליים</span></label>
      </div>
      <div class="card card-pad">
        <h3 class="card-title">תמונת הקטגוריה<small>העיגול בראש האתר. בלי תמונה מוצגת התמונה של המוצר הראשון</small></h3>
        <div style="display:flex;align-items:center;gap:16px">
          <label class="color-photo${d.image || fallback ? " has-img" : ""}" style="width:96px;height:96px;border-radius:50%">
            ${d.image || fallback ? imgTag(d.image || fallback) : `<span class="photo-cta">${icon("camera")}</span>`}
            <input type="file" accept="image/*" data-photo="category" aria-label="תמונת קטגוריה">
          </label>
          <div class="stack" style="gap:8px">
            <span class="field-hint">${d.image ? "תמונה שנבחרה" : "תמונה אוטומטית"}</span>
            ${d.image ? `<button class="btn btn-ghost btn-sm" type="button" data-action="category-image-auto">חזרה לתמונה אוטומטית</button>` : ""}
          </div>
        </div>
      </div>
      <div class="card card-pad">
        <label class="switch-row"><span class="switch-text"><b>רקע סטודיו</b><small>לתמונות מוצר על רקע לבן: הרקע מתמזג לאפור אחיד בכרטיסים</small></span><input type="checkbox" class="switch" data-bind="studio" ${d.studio ? "checked" : ""}></label>
      </div>
      ${
        !E.isNew && E.count
          ? `<p class="inline-note">יש ${E.count} מוצרים בקטגוריה. כדי למחוק אותה, קודם מעבירים אותם לקטגוריה אחרת או מוחקים אותם.</p>`
          : ""
      }`;
  }

  async function saveCategory() {
    const c = clone(E.draft);
    c.name = c.name.trim();
    if (!c.image) delete c.image;
    if (!c.studio) delete c.studio;
    const files = filesFor([c.image]);
    await save(`קטגוריה: ${c.name}`, {
      files,
      mutate: (d) => {
        const i = d.categories.findIndex((x) => x.id === c.id);
        if (i >= 0) d.categories[i] = c;
        else d.categories.push(c);
      },
    });
    forget(files);
    return E.isNew ? "הקטגוריה נוספה" : "הקטגוריה נשמרה";
  }

  async function removeCategory() {
    const id = E.draft.id;
    await save(`מחיקת קטגוריה: ${E.draft.name}`, {
      mutate: (d) => {
        if (d.products.some((p) => p.category === id)) throw new Error("יש מוצרים בקטגוריה. מעבירים אותם קודם לקטגוריה אחרת.");
        d.categories = d.categories.filter((c) => c.id !== id);
        d.deals = d.deals.filter((x) => !(x.type === "bundle" && x.category === id) && !(x.type === "percent" && x.scope === id));
      },
    });
    return "הקטגוריה נמחקה";
  }

  // ----- look editor -----
  function lookEditor(index) {
    const isNew = index == null;
    const look = isNew ? [] : S.data.looks[index];
    return {
      kind: "look",
      draft: { refs: [...look] },
      isNew,
      original: isNew ? null : JSON.stringify(look),
      title: isNew ? "לוק חדש" : "עריכת לוק",
      render: lookForm,
      validate: () => (E.draft.refs.filter((r) => resolveRef(S.data, r)).length < 2 ? "בלוק צריכים להיות לפחות 2 פריטים" : null),
      save: saveLook,
      remove: isNew ? null : removeLook,
      removeText: "למחוק את הלוק?",
    };
  }

  function lookForm() {
    const d = S.data;
    const refs = E.draft.refs;
    return `
      <div class="card card-pad">
        <h3 class="card-title">פריטים בלוק<small>בדרך כלל: חולצה או קפוצ'ון, מכנס ונעליים. עד 4 פריטים</small></h3>
        <div class="slots">${refs
          .map((ref, i) => {
            const it = resolveRef(d, ref);
            return it
              ? `<div class="slot">
                  ${thumb(it.c.image, studioClass(it.p.category))}
                  <div class="row-main"><span class="row-title">${esc(itemName(it.p, it.c))}</span><span class="row-meta">${esc(category(it.p.category)?.name || "")}${it.p.hidden ? ` · <span class="badge">מוסתר</span>` : ""}</span></div>
                  <button class="icon-btn" type="button" data-action="look-remove" data-index="${i}" aria-label="הסרה מהלוק">${icon("trash")}</button>
                </div>`
              : `<div class="slot missing">
                  ${thumb(null)}
                  <div class="row-main"><span class="row-title">פריט שנמחק</span></div>
                  <button class="icon-btn" type="button" data-action="look-remove" data-index="${i}" aria-label="הסרה מהלוק">${icon("trash")}</button>
                </div>`;
          })
          .join("")}</div>
        ${refs.length < 4 ? `<button class="add-tile" type="button" data-action="look-add" style="width:100%;margin-top:${refs.length ? 10 : 0}px">${icon("plus")}הוספת פריט</button>` : ""}
      </div>
      <p class="inline-note" style="margin-top:14px">הלוק יוצג בדף של כל אחד מהפריטים, תחת "השלם את הלוק".</p>`;
  }

  async function saveLook() {
    const d = S.data;
    const refs = E.draft.refs.filter((r) => resolveRef(d, r)).sort((a, b) => roleOfRef(d, a) - roleOfRef(d, b));
    const original = E.original;
    await save("לוק", {
      mutate: (data) => {
        const i = original ? data.looks.findIndex((l) => JSON.stringify(l) === original) : -1;
        if (i >= 0) data.looks[i] = refs;
        else data.looks.unshift(refs);
      },
    });
    return E.isNew ? "הלוק נוסף" : "הלוק נשמר";
  }

  async function removeLook() {
    const original = E.original;
    await save("מחיקת לוק", {
      mutate: (data) => {
        const i = data.looks.findIndex((l) => JSON.stringify(l) === original);
        if (i >= 0) data.looks.splice(i, 1);
      },
    });
    return "הלוק נמחק";
  }

  // ----- item picker (for looks) -----
  const picker = $("#picker");
  let pick = { cat: "all", onPick: null, taken: [] };

  function openPicker(onPick, taken) {
    pick = { cat: "all", onPick, taken };
    $("#pickerSearch").value = "";
    renderPicker();
    picker.showModal();
  }

  function renderPicker() {
    const d = S.data;
    const q = $("#pickerSearch").value.trim().toLowerCase();
    const counts = (id) => d.products.filter((p) => !p.hidden && p.category === id).reduce((n, p) => n + p.colors.length, 0);
    $("#pickerChips").innerHTML = [{ id: "all", name: "הכל" }, ...d.categories.filter((c) => counts(c.id))]
      .map(
        (c) =>
          `<button class="chip" type="button" data-action="picker-cat" data-cat="${esc(c.id)}" aria-pressed="${pick.cat === c.id}">${esc(c.name)}</button>`
      )
      .join("");
    const items = d.products
      .filter((p) => !p.hidden && (pick.cat === "all" || p.category === pick.cat))
      .flatMap((p) => p.colors.map((c) => ({ p, c, ref: itemRef(p, c), name: itemName(p, c) })))
      .filter((it) => !q || it.name.toLowerCase().includes(q));
    $("#pickerGrid").innerHTML = items.length
      ? items
          .map(
            (it) => `<button class="pick${pick.taken.includes(it.ref) ? " selected" : ""}" type="button" data-action="pick-item" data-ref="${esc(it.ref)}">
              ${thumb(it.c.image, studioClass(it.p.category))}
              <span>${esc(it.p.name)}${it.p.colors.length > 1 ? `<br><small>${esc(it.c.name)}</small>` : ""}</span>
            </button>`
          )
          .join("")
      : `<div class="empty" style="grid-column:1/-1">לא נמצאו פריטים</div>`;
    hydrate(picker);
  }

  // ---------- actions ----------
  const ACTIONS = {
    filter: (el) => {
      S.filter = el.dataset.cat;
      $$("[data-action='filter']").forEach((b) => b.setAttribute("aria-pressed", b === el));
      renderProductList();
    },
    "new-product": () => openEditor(productEditor(null)),
    "edit-product": (el) => {
      const p = S.data.products.find((x) => x.id === el.dataset.id);
      if (p) openEditor(productEditor(p));
    },
    "new-deal": () => openEditor(dealEditor(null)),
    "edit-deal": (el) => {
      const x = S.data.deals.find((y) => y.id === el.dataset.id);
      if (x) openEditor(dealEditor(x));
    },
    "new-category": () => openEditor(categoryEditor(null)),
    "edit-category": (el) => {
      const c = S.data.categories.find((x) => x.id === el.dataset.id);
      if (c) openEditor(categoryEditor(c));
    },
    "new-look": () => openEditor(lookEditor(null)),
    "edit-look": (el) => openEditor(lookEditor(+el.dataset.index)),

    "close-editor": () => requestClose(),
    delete: () => {
      if (E && E.kind === "category" && E.count) {
        $("#editorError").textContent = "אי אפשר למחוק קטגוריה שיש בה מוצרים";
        return;
      }
      deleteFromEditor();
    },

    // product editor
    "add-color": () => {
      E.draft.colors.push(newColor(E.draft));
      renderEditor();
      $$(".color-card", editorBody).pop()?.scrollIntoView({ behavior: "smooth", block: "center" });
    },
    "color-up": (el) => moveColor(+el.dataset.ci, -1),
    "color-down": (el) => moveColor(+el.dataset.ci, 1),
    "color-remove": async (el) => {
      const c = E.draft.colors[+el.dataset.ci];
      if (c.image && !(await confirmBox(`להסיר את הצבע${c.name ? ` "${c.name}"` : ""}?`, { ok: "הסרה", danger: true }))) return;
      E.draft.colors.splice(+el.dataset.ci, 1);
      renderEditor();
    },
    "toggle-out": (el) => {
      const c = E.draft.colors[+el.dataset.ci];
      const s = el.dataset.size;
      c.soldOut = c.soldOut.includes(s) ? c.soldOut.filter((x) => x !== s) : [...c.soldOut, s];
      const out = c.soldOut.includes(s);
      el.classList.toggle("is-out", out);
      el.setAttribute("aria-pressed", out);
    },
    "remove-size": (el) => {
      E.draft.sizes = E.draft.sizes.filter((s) => s !== el.dataset.size);
      renderEditor();
    },
    "size-preset": (el) => {
      E.draft.sizes = [...SIZE_PRESETS[+el.dataset.index][1]];
      renderEditor();
    },
    "add-size": () => addSize(),
    "toggle-sale": (el) => {
      E.draft.sale = el.checked ? { price: null, until: null } : null;
      renderEditor();
      if (el.checked) $("[data-bind='sale.price']", editorBody)?.focus();
    },
    "toggle-new": (el) => (E.draft.tag = el.checked ? "new" : null),

    // category editor
    "category-image-auto": () => {
      E.draft.image = null;
      renderEditor();
    },

    // look editor + picker
    "look-add": () =>
      openPicker((ref) => {
        if (!E.draft.refs.includes(ref)) E.draft.refs.push(ref);
        E.draft.refs.sort((a, b) => roleOfRef(S.data, a) - roleOfRef(S.data, b));
        renderEditor();
      }, E.draft.refs),
    "look-remove": (el) => {
      E.draft.refs.splice(+el.dataset.index, 1);
      renderEditor();
    },
    "picker-cat": (el) => {
      pick.cat = el.dataset.cat;
      renderPicker();
    },
    "pick-item": (el) => {
      picker.close();
      pick.onPick?.(el.dataset.ref);
    },
    "close-picker": () => picker.close(),

    // deals list
    "toggle-deal": (el) => toggleDeal(el),

    // settings
    "add-hours": () => {
      SET.draft.hours.push({ days: "", time: "" });
      renderView();
      $$(".hours-row input", view).at(-2)?.focus();
    },
    "remove-hours": (el) => {
      SET.draft.hours.splice(+el.dataset.index, 1);
      renderView();
    },
    "reset-settings": () => {
      SET = null;
      renderView();
    },
    "save-settings": (el) => saveSettings(el),
    logout: async () => {
      if (!(await confirmBox("להתנתק מהמכשיר הזה?", { ok: "התנתקות" }))) return;
      clearSession();
      location.reload();
    },

    // sign in
    "show-setup": () => showSetup(true),
    "show-login": () => showLogin(),
  };

  function moveColor(i, dir) {
    const cs = E.draft.colors;
    const j = i + dir;
    if (j < 0 || j >= cs.length) return;
    [cs[i], cs[j]] = [cs[j], cs[i]];
    renderEditor();
  }

  function addSize() {
    const input = $("#sizeInput");
    const s = input.value.trim().toUpperCase();
    if (!s) return;
    if (!E.draft.sizes.includes(s)) E.draft.sizes.push(s);
    renderEditor();
    $("#sizeInput").focus();
  }

  document.addEventListener("click", (e) => {
    const nav = e.target.closest("[data-view]");
    if (nav) return show(nav.dataset.view, true);
    const el = e.target.closest("[data-action]");
    // switches act on "change" below, and a drag handle never opens its row
    if (!el || el.tagName === "INPUT" || e.target.closest(".drag")) return;
    ACTIONS[el.dataset.action]?.(el, e);
  });
  document.addEventListener("change", (e) => {
    const el = e.target;
    if (el.tagName === "INPUT" && el.dataset.action) ACTIONS[el.dataset.action]?.(el, e);
  });

  // editor fields write straight into the draft
  editorBody.addEventListener("input", (e) => {
    const el = e.target;
    if (!E || !el.dataset.bind) return;
    setPath(E.draft, el.dataset.bind, inputValue(el));
    // naming a new colour picks its swatch
    if (el.dataset.colorName != null) {
      const c = E.draft.colors[+el.dataset.colorName];
      if (!c._hexSet) {
        const h = hexFor(c.name.trim());
        if (h) {
          c.hex = h;
          const sw = el.closest(".color-line").querySelector("input[type='color']");
          if (sw) sw.value = h;
        }
      }
    }
    if (el.type === "color") E.draft.colors[+el.dataset.bind.split(".")[1]]._hexSet = true;
    E.live?.();
  });
  editorBody.addEventListener("change", async (e) => {
    const el = e.target;
    if (!E) return;
    if (el.dataset.bind) {
      setPath(E.draft, el.dataset.bind, inputValue(el));
      if (el.dataset.rerender != null) renderEditor();
      E.live?.();
    }
    if (el.dataset.photo != null && el.files && el.files[0]) {
      const box = el.closest(".color-photo");
      box.classList.add("is-busy");
      try {
        const ref = await uploadPhoto(el.files[0]);
        if (!E) return;
        if (el.dataset.photo === "category") E.draft.image = ref;
        else E.draft.colors[+el.dataset.photo].image = ref;
        renderEditor();
      } catch {
        box.classList.remove("is-busy");
        toast("לא הצלחנו לקרוא את התמונה. נסו תמונה אחרת.", true);
      }
    }
  });
  editorBody.addEventListener("toggle", (e) => {
    if (e.target.id === "advanced" && E) E.advancedOpen = e.target.open;
  }, true);
  editorBody.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.id === "sizeInput") {
      e.preventDefault();
      addSize();
    }
  });
  $("#editorForm").addEventListener("submit", (e) => {
    e.preventDefault();
    submitEditor();
  });
  editor.addEventListener("cancel", (e) => {
    e.preventDefault();
    requestClose();
  });
  // closed by the browser itself (some phones' back gesture): keep unsaved work
  editor.addEventListener("close", () => {
    if (!E) return;
    if (editorDirty()) {
      editor.showModal();
      requestClose();
    } else {
      E = null;
      if (history.state && history.state.editor) history.back();
    }
  });
  picker.addEventListener("cancel", (e) => {
    e.preventDefault();
    picker.close();
  });
  $("#pickerSearch").addEventListener("input", renderPicker);

  // the phone's back button closes the window instead of leaving the panel
  addEventListener("popstate", () => {
    if (!E || !editor.open) return;
    history.pushState({ editor: true }, "", location.hash);
    if (picker.open) picker.close();
    else requestClose();
  });

  view.addEventListener("input", (e) => {
    const el = e.target;
    if (el.id === "productSearch") {
      S.query = el.value;
      renderProductList();
    } else if (el.id === "lookSearch") {
      S.lookQuery = el.value;
      const pos = el.selectionStart;
      renderView();
      const again = $("#lookSearch");
      again.focus();
      again.setSelectionRange(pos, pos);
    } else if (el.dataset.sbind && SET) {
      setPath(SET.draft, el.dataset.sbind, inputValue(el));
      updateSettingsBar();
    }
  });
  view.addEventListener("change", (e) => {
    const el = e.target;
    if (el.dataset.sbind && SET && el.type === "checkbox") {
      setPath(SET.draft, el.dataset.sbind, inputValue(el));
      updateSettingsBar();
    }
  });
  view.addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector("button[type='submit']");
    if (form.id === "passwordForm") {
      const { password, password2 } = Object.fromEntries(new FormData(form));
      if (password.length < 8) return toast("סיסמה של 8 תווים לפחות", true);
      if (password !== password2) return toast("הסיסמאות לא זהות", true);
      busyButton(btn, true);
      try {
        await writeVault(password, { token: S.token, code: S.code });
        form.reset();
        toast("הסיסמה הוחלפה. מעכשיו נכנסים עם הסיסמה החדשה");
      } catch (err) {
        toast(errorText(err), true);
      }
      busyButton(btn, false);
    } else if (form.id === "tokenForm") {
      const { token, password } = Object.fromEntries(new FormData(form));
      if (!token.trim()) return toast("חסר טוקן", true);
      busyButton(btn, true);
      try {
        const vault = await fetchVault();
        try {
          await openVault(password, vault);
        } catch {
          throw new Error("סיסמת הניהול לא נכונה");
        }
        await gh("", { token: token.trim() });
        const old = S.token;
        S.token = token.trim();
        try {
          await writeVault(password, { token: S.token, code: S.code });
        } catch (err) {
          S.token = old;
          throw err;
        }
        rememberSession();
        form.reset();
        toast("הטוקן הוחלף");
      } catch (err) {
        toast(errorText(err), true);
      }
      busyButton(btn, false);
    }
  });

  addEventListener("beforeunload", (e) => {
    if (pending || editorDirty() || settingsDirty()) {
      e.preventDefault();
      e.returnValue = "";
    }
  });

  // ---------- sign in ----------
  const auth = $("#auth");
  const loginForm = $("#loginForm");
  const setupForm = $("#setupForm");
  const authStatus = $("#authStatus");
  let hasVault = false;

  function readSession() {
    for (const store of [sessionStorage, localStorage]) {
      try {
        const s = JSON.parse(store.getItem(SESSION_KEY) || "null");
        if (s && s.token && s.code) return s;
      } catch {
        /* storage unavailable */
      }
    }
    return null;
  }
  let remember = true;
  function rememberSession() {
    const value = JSON.stringify({ token: S.token, code: S.code });
    try {
      (remember ? localStorage : sessionStorage).setItem(SESSION_KEY, value);
    } catch {
      /* this visit only */
    }
  }
  function clearSession() {
    for (const store of [sessionStorage, localStorage]) {
      try {
        store.removeItem(SESSION_KEY);
      } catch {
        /* ignore */
      }
    }
  }

  async function fetchVault() {
    const r = await fetch(`vault.json?t=${Date.now()}`, { cache: "no-store" }).catch(() => null);
    if (r && r.ok) return r.json();
    // just created and not on the site yet: read it from the repo (public)
    try {
      return JSON.parse(dec.decode(await gh(`contents/${VAULT_PATH}?ref=${CONFIG.branch}`, { raw: true, token: null })));
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }

  async function writeVault(password, secrets) {
    await save("הגדרות גישה לניהול", { files: [{ path: VAULT_PATH, bytes: enc.encode(await sealVault(password, secrets)) }] });
  }

  async function signIn(secrets) {
    S.token = secrets.token;
    S.code = secrets.code;
    S.key = await siteKeyFor(secrets.code);
    S.data = await readData(await headSha());
  }

  function enterPanel() {
    auth.hidden = true;
    $("#shell").hidden = false;
    show(location.hash.slice(1) || "products");
  }

  function showLogin() {
    setupForm.hidden = true;
    loginForm.hidden = false;
    authStatus.textContent = "";
    $(".form-error", loginForm).textContent = "";
    loginForm.elements.password.focus();
  }

  function showSetup(reset) {
    loginForm.hidden = true;
    setupForm.hidden = false;
    authStatus.textContent = "";
    $(".form-error", setupForm).textContent = "";
    $("[data-action='show-login']", setupForm).hidden = !hasVault;
    $(".setup-intro h1", setupForm).textContent = reset && hasVault ? "הגדרה מחדש" : "הגדרה ראשונית";
    setupForm.elements.code.focus();
  }

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("button[type='submit']", loginForm);
    const error = $(".form-error", loginForm);
    const password = loginForm.elements.password.value;
    if (!password) return;
    error.textContent = "";
    busyButton(btn, true);
    authStatus.textContent = "בודק סיסמה…";
    try {
      let secrets;
      try {
        secrets = await openVault(password, await fetchVault());
      } catch (err) {
        if (err instanceof ApiError) throw err;
        throw new Error("סיסמה שגויה");
      }
      authStatus.textContent = "טוען את החנות…";
      try {
        await signIn(secrets);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401)
          throw new Error('הטוקן של GitHub פג או בוטל. לחצו על "שכחתי סיסמה / החלפת טוקן" והזינו טוקן חדש.');
        throw err;
      }
      remember = loginForm.elements.remember.checked;
      rememberSession();
      enterPanel();
    } catch (err) {
      error.textContent = errorText(err);
      authStatus.textContent = "";
      loginForm.elements.password.select();
    }
    busyButton(btn, false);
  });

  setupForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("button[type='submit']", setupForm);
    const error = $(".form-error", setupForm);
    const f = setupForm.elements;
    const code = f.code.value.replace(/\D/g, "");
    const token = f.token.value.trim();
    const password = f.password.value;
    error.textContent = "";
    if (code.length !== 6) return (error.textContent = "קוד הכניסה הוא 6 ספרות");
    if (!token) return (error.textContent = "חסר טוקן GitHub");
    if (password.length < 8) return (error.textContent = "סיסמה של 8 תווים לפחות");
    if (password !== f.password2.value) return (error.textContent = "הסיסמאות לא זהות");
    busyButton(btn, true);
    try {
      authStatus.textContent = "בודק את הטוקן…";
      S.token = token;
      await gh("");
      authStatus.textContent = "בודק את קוד הכניסה…";
      try {
        await signIn({ token, code });
      } catch (err) {
        if (err instanceof ApiError) throw err;
        throw new Error("קוד הכניסה לא נכון");
      }
      authStatus.textContent = "שומר…";
      await writeVault(password, { token, code });
      remember = true;
      rememberSession();
      enterPanel();
      toast("ההגדרה הושלמה. מעכשיו נכנסים רק עם הסיסמה");
    } catch (err) {
      error.textContent = errorText(err);
      authStatus.textContent = "";
    }
    busyButton(btn, false);
  });

  async function start() {
    if (!window.crypto || !crypto.subtle) {
      auth.hidden = false;
      authStatus.textContent = "הדפדפן הזה לא נתמך. פתחו את הקישור ב-Chrome או ב-Safari.";
      return;
    }
    const saved = readSession();
    if (saved) {
      auth.hidden = false;
      authStatus.textContent = "טוען את החנות…";
      try {
        await signIn(saved);
        remember = (() => {
          try {
            return !!localStorage.getItem(SESSION_KEY);
          } catch {
            return false;
          }
        })();
        return enterPanel();
      } catch (err) {
        if (err instanceof ApiError && err.status === 0) {
          auth.hidden = false;
          authStatus.textContent = errorText(err);
          return;
        }
        clearSession();
      }
    }
    auth.hidden = false;
    authStatus.textContent = "טוען…";
    try {
      const vault = await fetchVault();
      hasVault = !!vault;
      if (hasVault) showLogin();
      else showSetup(false);
    } catch (err) {
      authStatus.textContent = errorText(err);
    }
  }

  start();
})();

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadNacl() {
    const filePath = path.join(__dirname, "..", "DuxKeePassXC.qml");
    const raw = fs.readFileSync(filePath, "utf8");
    const marker = "\n    function _createNacl() {";
    const startIdx = raw.indexOf(marker);
    assert.notEqual(startIdx, -1, "_createNacl() not found in DuxKeePassXC.qml");
    const endMarker = "\n    }\n";
    const endIdx = raw.indexOf(endMarker, startIdx + marker.length);
    assert.notEqual(endIdx, -1, "closing brace for _createNacl() not found in DuxKeePassXC.qml");
    const fnSource = raw.slice(startIdx + 1, endIdx + endMarker.length);
    const context = vm.createContext({
        Uint8Array,
        Int16Array,
        Int32Array,
        Uint32Array,
        Float64Array,
        Array,
        Object,
        String,
        Math,
        Date,
        JSON,
        Error
    });
    vm.runInContext(fnSource + "\nvar _nacl = _createNacl();\n", context, { filename: filePath });
    return context._nacl;
}

const Nacl = loadNacl();

test("CSPRNG fails closed until seeded with at least 32 bytes", () => {
    const fresh = loadNacl();
    assert.equal(fresh.isSeeded(), false);
    assert.throws(() => fresh.randomBytes(16), /CSPRNG not seeded/);
    fresh.seedEntropy([1, 2, 3, 4]);
    assert.equal(fresh.isSeeded(), false);
    assert.throws(() => fresh.randomBytes(16), /CSPRNG not seeded/);
    fresh.seedEntropy(new Array(28).fill(7));
    assert.equal(fresh.isSeeded(), true);
    const r = fresh.randomBytes(24);
    assert.equal(r.length, 24);
});

test("matches C NaCl / golang.org/x/crypto/nacl/box reference vector", () => {
    const sk1 = new Uint8Array(32).fill(1);
    const sk2 = new Uint8Array(32).fill(2);
    const kp1 = Nacl.boxKeyPairFromSecretKey(sk1);
    const kp2 = Nacl.boxKeyPairFromSecretKey(sk2);

    const message = new Uint8Array(64).fill(3);
    const nonce = new Uint8Array(24).fill(4);

    const sealed = Nacl.box(message, nonce, kp1.publicKey, sk2);
    const gotHex = Buffer.from(sealed).toString("hex");
    const expectedHex =
        "78ea30b19d2341ebbdba54180f821eec265cf86312549bea8a37652a8bb94f07" +
        "b78a73ed1708085e6ddd0e943bbdeb8755079a37eb31d86163ce241164a47629" +
        "c0539f330b4914cd135b3855bc2a2dfc";

    assert.equal(gotHex, expectedHex);

    const opened = Nacl.boxOpen(sealed, nonce, kp2.publicKey, sk1);
    assert.ok(opened !== null);
    assert.deepEqual(Buffer.from(opened), Buffer.from(message));
});

test("box and boxOpen round-trip and tamper detection", () => {
    Nacl.seedEntropy(new Array(32).fill(0).map((_, i) => (i * 17 + 42) & 0xff));
    const alice = Nacl.boxKeyPair();
    const bob = Nacl.boxKeyPair();
    const nonce = Nacl.randomBytes(24);

    const payload = JSON.stringify({
        action: "get-logins",
        url: "keepassxc://by-uuid/1234",
        unicode: "héllo 🔐 世界"
    });
    const plain = Nacl.encodeUTF8(payload);
    const cipher = Nacl.box(plain, nonce, bob.publicKey, alice.secretKey);

    const decrypted = Nacl.boxOpen(cipher, nonce, alice.publicKey, bob.secretKey);
    assert.ok(decrypted !== null);
    assert.equal(Nacl.decodeUTF8(decrypted), payload);

    // Every single bit flip in cipher must fail authentication
    for (let i = 0; i < cipher.length; i++) {
        const corrupted = new Uint8Array(cipher);
        corrupted[i] ^= 0x40;
        assert.equal(Nacl.boxOpen(corrupted, nonce, alice.publicKey, bob.secretKey), null);
    }

    // Wrong nonce must fail
    const badNonce = Nacl.incrementNonce(nonce);
    assert.equal(Nacl.boxOpen(cipher, badNonce, alice.publicKey, bob.secretKey), null);
});

test("incrementNonce carries little-endian across bytes", () => {
    const n1 = new Uint8Array(24);
    n1[0] = 0xff;
    n1[1] = 0xff;
    n1[2] = 0x05;

    const n2 = Nacl.incrementNonce(n1);
    assert.equal(n1[0], 0xff); // non-mutating
    assert.equal(n2[0], 0x00);
    assert.equal(n2[1], 0x00);
    assert.equal(n2[2], 0x06);
});

test("base64 and utf8 round-trip", () => {
    for (const s of ["", "a", "ab", "abc", "abcd", "p@ssw0rd! 🔑 äöü 日本語"]) {
        const bytes = Nacl.encodeUTF8(s);
        const b64 = Nacl.encodeBase64(bytes);
        assert.equal(b64, Buffer.from(s, "utf8").toString("base64"));
        const decoded = Nacl.decodeBase64(b64);
        assert.equal(Nacl.decodeUTF8(decoded), s);
    }
});

test("extractJsonObjects handles partial chunks, concatenated objects, and braces in strings", () => {
    const chunk1 = '{"action":"database-locked"}{"action":"get-logins","note":"braces { } \\"quoted\\""';
    const r1 = Nacl.extractJsonObjects(chunk1);
    assert.equal(r1.objects.length, 1);
    assert.equal(r1.objects[0].action, "database-locked");
    assert.ok(r1.rest.startsWith('{"action":"get-logins"'));

    const chunk2 = r1.rest + ',"success":"true"}   {"action":"database-unlocked"}';
    const r2 = Nacl.extractJsonObjects(chunk2);
    assert.equal(r2.objects.length, 2);
    assert.equal(r2.objects[0].note, 'braces { } "quoted"');
    assert.equal(r2.objects[0].success, "true");
    assert.equal(r2.objects[1].action, "database-unlocked");
    assert.equal(r2.rest, "");
});

test("flattenGroupPaths extracts paths with and without root prefix", () => {
    const payload = {
        groups: [
            {
                name: "Root",
                children: [
                    {
                        name: "Dev",
                        children: [
                            { name: "Git", children: [] }
                        ]
                    },
                    { name: "Finance", children: [] }
                ]
            }
        ]
    };
    const paths = Array.from(Nacl.flattenGroupPaths(payload));
    assert.deepEqual(paths, [
        "Root",
        "Root/Dev",
        "Root/Dev/Git",
        "Root/Finance",
        "Dev",
        "Dev/Git",
        "Finance"
    ]);
});

test("buildSearchCandidates constructs by-path and domain URLs", () => {
    const candidates = Array.from(Nacl.buildSearchCandidates("github", ["Dev", "Finance"]));
    assert.deepEqual(candidates, [
        "keepassxc://by-path/github",
        "keepassxc://by-path/Dev/github",
        "keepassxc://by-path/Finance/github",
        "https://github.com",
        "https://github.org",
        "https://github.net",
        "https://github.io",
        "https://github.dev"
    ]);

    assert.deepEqual(
        Array.from(Nacl.buildSearchCandidates("https://example.org/login", ["Dev"])),
        ["https://example.org/login"]
    );
});

test("bytesEqual compares byte arrays in constant-shape manner", () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    const c = new Uint8Array([1, 2, 3, 5]);
    const d = new Uint8Array([1, 2, 3]);
    assert.equal(Nacl.bytesEqual(a, b), true);
    assert.equal(Nacl.bytesEqual(a, c), false);
    assert.equal(Nacl.bytesEqual(a, d), false);
    assert.equal(Nacl.bytesEqual(null, a), false);
});

test("isUrlSchemeAllowed enforces configurable scheme whitelist", () => {
    assert.equal(Nacl.isUrlSchemeAllowed("https://example.com/login", "http, https"), true);
    assert.equal(Nacl.isUrlSchemeAllowed("HTTP://example.com", "http, https"), true);
    assert.equal(Nacl.isUrlSchemeAllowed("file:///etc/passwd", "http, https"), false);
    assert.equal(Nacl.isUrlSchemeAllowed("cmd://calc", "http, https"), false);
    assert.equal(Nacl.isUrlSchemeAllowed("javascript:alert(1)", "http, https"), false);
    assert.equal(Nacl.isUrlSchemeAllowed("https://example.com\nrm -rf /", "http, https"), false);
    assert.equal(Nacl.isUrlSchemeAllowed("ssh://host.internal", "http, https"), false);
    assert.equal(Nacl.isUrlSchemeAllowed("ssh://host.internal", "http, https, ssh"), true);
    assert.equal(Nacl.isUrlSchemeAllowed("https://example.com", ""), false);
});

test("isEmptyUrlCrashVersion identifies KeePassXC 2.7.x and 2.8.0", () => {
    assert.equal(Nacl.isEmptyUrlCrashVersion("2.8.0"), true);
    assert.equal(Nacl.isEmptyUrlCrashVersion("2.7.10"), true);
    assert.equal(Nacl.isEmptyUrlCrashVersion("2.8.1"), false);
    assert.equal(Nacl.isEmptyUrlCrashVersion("2.9.0"), false);
    assert.equal(Nacl.isEmptyUrlCrashVersion("3.0.0"), false);
    assert.equal(Nacl.isEmptyUrlCrashVersion(""), false);
});

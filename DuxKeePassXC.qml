import QtQuick
import Quickshell
import Quickshell.Io
import qs.Common
import qs.Services

QtObject {
    id: root

    property var pluginService: null
    property string pluginId: "duxKeePassXC"
    property string trigger: "["
    property string defaultAction: "copy:password"
    property int clearSeconds: 15
    property bool pasteOnce: false
    property string storeMode: "auto"
    property string customSocketPath: ""
    property bool persistMetadataCache: false
    property string allowedUrlSchemes: "http, https"
    property bool guardEmptyUrlCrash: true

    property string _status: "loading"
    property string _errorMessage: ""
    property string _secretServiceWarning: ""
    property bool _warnedSecretService: false
    property bool _secretServiceDetected: false
    property string _activeStoreBackend: "file"

    property bool _restrictedMode: false
    property string _restrictedWarning: ""
    property bool _warnedRestrictedMode: false
    property string _pendingSearchQuery: ""
    property string _lastSearchedQuery: ""

    property var _entries: []
    property var _groupPaths: []
    property var _mruIds: []
    property var _metaCache: ({})
    property var _fieldsCache: ({})
    property var _fieldsPending: ({})
    property string _selectedCategory: "all"
    property bool _loading: false
    property bool _reloadingSettings: false
    property bool _startupDone: false

    property var _associations: ({})
    property string _currentDbHash: ""

    // Socket & NaCl session state
    property string _activeSocketPath: ""
    property bool _socketReady: false
    property bool _handshaking: false
    property var _sessionKeyPair: null
    property var _serverPublicKey: null
    property string _clientId: ""
    property var _handshakeNonce: null
    property string _serverVersion: ""
    property string _rxBuffer: ""
    property var _inflightReq: null
    property var _requestQueue: []

    readonly property string _homeDir: Quickshell.env("HOME") || ""
    readonly property string _localDataDir: (Quickshell.env("XDG_DATA_HOME") || (_homeDir + "/.local/share")) + "/dms/duxKeePassXC"
    readonly property string _localAssocFile: _localDataDir + "/associations.json"
    readonly property var nacl: _createNacl()

    signal itemsChanged()

    Component.onCompleted: {
        if (pluginService) {
            _reloadSettings();
            const savedMru = pluginService.loadPluginState(pluginId, "mruIds", []);
            if (Array.isArray(savedMru)) {
                _mruIds = savedMru;
            }
            const savedMeta = pluginService.loadPluginState(pluginId, "metaCache", ({}));
            if (persistMetadataCache) {
                if (savedMeta && typeof savedMeta === "object") {
                    _metaCache = savedMeta;
                }
            } else {
                _metaCache = ({});
                if (savedMeta && typeof savedMeta === "object" && Object.keys(savedMeta).length > 0) {
                    pluginService.savePluginState(pluginId, "metaCache", ({}));
                }
            }
        }
        Qt.callLater(_initStartup);
    }

    property var _pluginDataConn: Connections {
        target: pluginService
        enabled: pluginService !== null
        function onPluginDataChanged(changedPluginId) {
            if (changedPluginId === root.pluginId) {
                root._reloadSettings();
            }
        }
    }

    onTriggerChanged: {
        if (!_reloadingSettings && pluginService) {
            pluginService.savePluginData(pluginId, "trigger", trigger);
            itemsChanged();
        }
    }

    function _reloadSettings() {
        if (!pluginService)
            return;
        const prevStore = storeMode;
        const prevSocket = customSocketPath;
        const prevPersist = persistMetadataCache;
        _reloadingSettings = true;
        try {
            const noTrigger = pluginService.loadPluginData(pluginId, "noTrigger", false);
            trigger = noTrigger ? "" : pluginService.loadPluginData(pluginId, "trigger", "[");
            defaultAction = pluginService.loadPluginData(pluginId, "defaultAction", "copy:password");

            const parsedClear = parseInt(pluginService.loadPluginData(pluginId, "clearSeconds", "15"), 10);
            clearSeconds = isNaN(parsedClear) ? 15 : parsedClear;

            pasteOnce = Boolean(pluginService.loadPluginData(pluginId, "pasteOnce", false));
            storeMode = pluginService.loadPluginData(pluginId, "storeMode", "auto") || "auto";
            customSocketPath = pluginService.loadPluginData(pluginId, "customSocketPath", "") || "";
            persistMetadataCache = Boolean(pluginService.loadPluginData(pluginId, "persistMetadataCache", false));
            allowedUrlSchemes = pluginService.loadPluginData(pluginId, "allowedUrlSchemes", "http, https");
            guardEmptyUrlCrash = Boolean(pluginService.loadPluginData(pluginId, "guardEmptyUrlCrash", true));
        } finally {
            _reloadingSettings = false;
        }

        if (prevPersist && !persistMetadataCache) {
            _metaCache = ({});
            pluginService.savePluginState(pluginId, "metaCache", ({}));
        }

        if (_startupDone && (prevSocket !== customSocketPath || prevStore !== storeMode)) {
            _disconnectSocket();
            _loadAssociations(() => refreshEntries(false));
        } else {
            itemsChanged();
            _notifyLauncherUpdate();
        }
    }

    function _notifyLauncherUpdate() {
        if (pluginService && typeof pluginService.requestLauncherUpdate === "function") {
            pluginService.requestLauncherUpdate(pluginId);
        }
    }

    function _showInfo(title, message) {
        if (typeof ToastService !== "undefined" && typeof ToastService.showInfo === "function") {
            ToastService.showInfo(title, message);
        }
    }

    function _showWarning(title, message) {
        if (typeof ToastService !== "undefined") {
            if (typeof ToastService.showWarning === "function") {
                ToastService.showWarning(title, message);
            } else if (typeof ToastService.showInfo === "function") {
                ToastService.showInfo(title, message);
            }
        }
    }

    function _showError(title, message) {
        if (typeof ToastService !== "undefined") {
            if (typeof ToastService.showError === "function") {
                ToastService.showError(title, message);
            } else if (typeof ToastService.showInfo === "function") {
                ToastService.showInfo(title, message);
            }
        }
    }

    // --- Startup: CSPRNG seeding + Secret Service detection + Association loading ---

    function _initStartup() {
        _seedEntropy(seededOk => {
            if (!seededOk) {
                root._status = "error";
                root._errorMessage = "Failed to read OS entropy from /dev/urandom";
                root._showError("Dux KeePassXC", root._errorMessage);
                root.itemsChanged();
                root._notifyLauncherUpdate();
                return;
            }
            _loadAssociations(() => {
                _startupDone = true;
                refreshEntries(false);
            });
        });
    }

    function _seedEntropy(done) {
        const script = 'od -An -tu1 -N64 /dev/urandom 2>/dev/null || hexdump -ve \'1/1 "%u "\' -n 64 /dev/urandom 2>/dev/null';
        _runProcess(["sh", "-c", script], null, (exitCode, outText) => {
            if (exitCode === 0 && outText) {
                const nums = outText.trim().split(/\s+/).map(s => parseInt(s, 10)).filter(n => !isNaN(n) && n >= 0 && n <= 255);
                if (nums.length >= 32) {
                    nacl.seedEntropy(nums);
                }
            }
            if (typeof done === "function")
                done(nacl.isSeeded());
        });
    }

    function _detectSecretService(done) {
        const script = [
            'cfg="${XDG_CONFIG_HOME:-$HOME/.config}/keepassxc/keepassxc.ini"',
            'data="${XDG_DATA_HOME:-$HOME/.local/share}/dbus-1/services/org.freedesktop.secrets.service"',
            'if [ -f "$cfg" ] && awk \'/^\\[/{s=tolower($0); next} s=="[fdosecrets]" && tolower($0) ~ /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true/{f=1} END{exit !f}\' "$cfg"; then',
            '  printf \'{"detected":true,"reason":"KeePassXC FdoSecrets is enabled in keepassxc.ini"}\\n\'',
            '  exit 0',
            'fi',
            'if [ -f "$data" ] && grep -qi "keepassxc" "$data" 2>/dev/null; then',
            '  printf \'{"detected":true,"reason":"org.freedesktop.secrets.service points to KeePassXC"}\\n\'',
            '  exit 0',
            'fi',
            'pid=""',
            'if command -v busctl >/dev/null 2>&1; then',
            '  pid=$(timeout 0.4 busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionUnixProcessID s org.freedesktop.secrets 2>/dev/null | awk \'{print $2}\')',
            'elif command -v gdbus >/dev/null 2>&1; then',
            '  pid=$(timeout 0.4 gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.GetConnectionUnixProcessID org.freedesktop.secrets 2>/dev/null | sed -n "s/.*uint32 \\([0-9]*\\).*/\\1/p")',
            'fi',
            'if [ -n "$pid" ] && [ -r "/proc/$pid/comm" ]; then',
            '  if grep -qi "keepassxc" "/proc/$pid/comm" 2>/dev/null || readlink "/proc/$pid/exe" 2>/dev/null | grep -qi "keepassxc"; then',
            '    printf \'{"detected":true,"reason":"org.freedesktop.secrets is currently owned by keepassxc"}\\n\'',
            '    exit 0',
            '  fi',
            'fi',
            'printf \'{"detected":false,"reason":""}\\n\''
        ].join("\n");

        _runProcess(["sh", "-c", script], null, (exitCode, outText) => {
            let detected = false;
            let reason = "";
            try {
                const parsed = JSON.parse((outText || "").trim());
                detected = Boolean(parsed.detected);
                reason = parsed.reason || "";
            } catch (e) {
                detected = false;
            }
            done(detected, reason);
        });
    }

    function _loadAssociations(done) {
        if (storeMode === "file") {
            _activeStoreBackend = "file";
            _loadAssociationsFromFile(done);
            return;
        }

        _detectSecretService((detected, reason) => {
            _secretServiceDetected = detected;
            if (detected) {
                _activeStoreBackend = "file";
                _secretServiceWarning = "Detected KeePassXC as org.freedesktop.secrets provider (" + reason + "); using local 0600 file store to avoid unlock deadlock.";
                if (!_warnedSecretService) {
                    _warnedSecretService = true;
                    _showWarning("Dux KeePassXC", _secretServiceWarning);
                }
                _loadAssociationsFromFile(done);
                return;
            }

            _runProcess(["sh", "-c", "command -v secret-tool >/dev/null 2>&1 && timeout 2 secret-tool lookup application duxKeePassXC type associations"], null, (exitCode, outText, errText) => {
                if (exitCode === 0 && outText && outText.trim().length > 0) {
                    try {
                        const parsed = JSON.parse(outText);
                        if (parsed && typeof parsed === "object") {
                            _activeStoreBackend = "keyring";
                            _associations = parsed;
                            if (typeof done === "function")
                                done();
                            return;
                        }
                    } catch (e) {
                        // Fall through to file fallback
                    }
                }

                // secret-tool exits 1 with empty stderr/stdout when no entry exists yet
                const errClean = (errText || "").trim();
                if (exitCode === 1 && errClean.length === 0 && (!outText || outText.trim().length === 0)) {
                    _activeStoreBackend = "keyring";
                    _loadAssociationsFromFile(done);
                    return;
                }

                _activeStoreBackend = "file";
                if (storeMode === "keyring" && errClean.length > 0 && !_warnedSecretService) {
                    _warnedSecretService = true;
                    _showWarning("Dux KeePassXC", "Keyring unavailable; using local 0600 file store.");
                }
                _loadAssociationsFromFile(done);
            });
        });
    }

    function _loadAssociationsFromFile(done) {
        _runProcess(["sh", "-c", 'cat "$1" 2>/dev/null || true', "_", _localAssocFile], null, (exitCode, outText) => {
            if (outText && outText.trim().length > 0) {
                try {
                    const parsed = JSON.parse(outText);
                    if (parsed && typeof parsed === "object") {
                        _associations = parsed;
                    }
                } catch (e) {
                    _associations = ({});
                }
            }
            if (typeof done === "function")
                done();
        });
    }

    function _saveAssociation(dbHash, id, idKey, done) {
        if (!dbHash || !id || !idKey) {
            if (typeof done === "function")
                done(false);
            return;
        }
        const next = Object.assign({}, _associations);
        next[dbHash] = {
            databaseHash: dbHash,
            id: id,
            idKey: idKey,
            createdAt: new Date().toISOString()
        };
        _associations = next;
        const jsonPayload = JSON.stringify(next, null, 2) + "\n";

        if (_activeStoreBackend === "keyring") {
            _runProcess(
                ["secret-tool", "store", "--label=Dux KeePassXC Associations", "application", "duxKeePassXC", "type", "associations"],
                jsonPayload,
                (exitCode) => {
                    if (exitCode === 0) {
                        if (typeof done === "function")
                            done(true);
                        return;
                    }
                    _activeStoreBackend = "file";
                    _saveAssociationsToFile(jsonPayload, done);
                }
            );
            return;
        }

        _saveAssociationsToFile(jsonPayload, done);
    }

    function _saveAssociationsToFile(jsonPayload, done) {
        const script = 'umask 077 && dir=$(dirname "$1") && mkdir -p "$dir" && chmod 700 "$dir" && tmp=$(mktemp "$dir/.associations.XXXXXX") || exit 1; if cat > "$tmp" && chmod 600 "$tmp" && mv "$tmp" "$1"; then exit 0; else rm -f "$tmp"; exit 1; fi';
        _runProcess(["sh", "-c", script, "_", _localAssocFile], jsonPayload, (exitCode) => {
            if (typeof done === "function")
                done(exitCode === 0);
        });
    }

    // --- KeePassXC BrowserServer Socket & NaCl Protocol ---

    property Socket kpxcSocket: Socket {
        id: kpxcSocket
        path: root._activeSocketPath
        connected: false

        parser: SplitParser {
            splitMarker: ""
            onRead: chunk => root._onSocketChunk(chunk)
        }

        onConnectionStateChanged: {
            root._onSocketStateChanged(connected);
        }

        onError: err => {
            root._onSocketError(err);
        }
    }

    property Timer requestTimeoutTimer: Timer {
        id: requestTimeoutTimer
        interval: 8000
        repeat: false
        onTriggered: {
            if (root._handshaking) {
                root._failAllRequests("TIMEOUT", "KeePassXC handshake timed out");
                root._disconnectSocket();
                return;
            }
            if (root._inflightReq) {
                const req = root._inflightReq;
                root._inflightReq = null;
                if (typeof req.callback === "function") {
                    req.callback({ code: "TIMEOUT", message: "KeePassXC request timed out" }, null);
                }
                root._pumpQueue();
            }
        }
    }

    function _clearLockedState() {
        _entries = [];
        _fieldsCache = ({});
        _fieldsPending = ({});
        _groupPaths = [];
        _lastSearchedQuery = "";
        _pendingSearchQuery = "";
    }

    function _disconnectSocket() {
        requestTimeoutTimer.stop();
        _socketReady = false;
        _handshaking = false;
        _rxBuffer = "";
        _sessionKeyPair = null;
        _serverPublicKey = null;
        _handshakeNonce = null;
        _serverVersion = "";
        if (kpxcSocket.connected) {
            kpxcSocket.connected = false;
        }
    }

    function _failAllRequests(code, message) {
        requestTimeoutTimer.stop();
        const errObj = { code: code, message: message };
        if (_inflightReq) {
            const req = _inflightReq;
            _inflightReq = null;
            if (typeof req.callback === "function") {
                req.callback(errObj, null);
            }
        }
        const pending = _requestQueue.slice();
        _requestQueue = [];
        for (let i = 0; i < pending.length; i++) {
            if (typeof pending[i].callback === "function") {
                pending[i].callback(errObj, null);
            }
        }
    }

    function _probeSocketPath(done) {
        const custom = (customSocketPath || "").trim();
        const script = [
            'if [ -n "$1" ]; then',
            '  [ -S "$1" ] && [ -O "$1" ] && printf "%s" "$1" && exit 0',
            '  exit 1',
            'fi',
            'uid=$(id -u)',
            'for p in \\',
            '  "${XDG_RUNTIME_DIR:-/run/user/$uid}/org.keepassxc.KeePassXC.BrowserServer" \\',
            '  "${XDG_RUNTIME_DIR:-/run/user/$uid}/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer" \\',
            '  "/run/user/$uid/org.keepassxc.KeePassXC.BrowserServer" \\',
            '  "/run/user/$uid/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer"; do',
            '  if [ -S "$p" ] && [ -O "$p" ]; then printf "%s" "$p"; exit 0; fi',
            'done',
            'exit 1'
        ].join("\n");

        _runProcess(["sh", "-c", script, "_", custom], null, (exitCode, outText) => {
            done(exitCode === 0 ? (outText || "").trim() : "");
        });
    }

    function _onSocketStateChanged(isConnected) {
        if (isConnected) {
            if (!nacl.isSeeded()) {
                _failAllRequests("NO_ENTROPY", "CSPRNG not seeded with OS entropy");
                _disconnectSocket();
                return;
            }
            _socketReady = false;
            _handshaking = true;
            _rxBuffer = "";
            _sessionKeyPair = nacl.boxKeyPair();
            const hsNonce = nacl.randomBytes(24);
            _handshakeNonce = hsNonce;
            _clientId = nacl.encodeBase64(nacl.randomBytes(24));

            requestTimeoutTimer.interval = 5000;
            requestTimeoutTimer.restart();
            _sendRaw({
                action: "change-public-keys",
                publicKey: nacl.encodeBase64(_sessionKeyPair.publicKey),
                nonce: nacl.encodeBase64(hsNonce),
                clientID: _clientId
            });
            return;
        }

        const wasConnectingOrReady = _handshaking || _socketReady || _inflightReq !== null || _requestQueue.length > 0;
        _socketReady = false;
        _handshaking = false;
        _rxBuffer = "";
        if (wasConnectingOrReady) {
            _failAllRequests("NOT_RUNNING", "Disconnected from KeePassXC");
        }
    }

    function _onSocketError(err) {
        _socketReady = false;
        _handshaking = false;
        _rxBuffer = "";
        _failAllRequests("NOT_RUNNING", "KeePassXC BrowserServer socket unavailable");
    }

    function _sendRaw(obj) {
        if (!kpxcSocket.connected)
            return false;
        kpxcSocket.write(JSON.stringify(obj));
        kpxcSocket.flush();
        return true;
    }

    function _onSocketChunk(chunk) {
        if (!chunk)
            return;
        _rxBuffer += chunk;
        const parsed = nacl.extractJsonObjects(_rxBuffer);
        _rxBuffer = parsed.rest;

        for (let i = 0; i < parsed.objects.length; i++) {
            _handleSocketMessage(parsed.objects[i]);
        }
    }

    function _handleSocketMessage(msg) {
        if (!msg || typeof msg !== "object")
            return;

        if (msg.action === "database-locked") {
            _status = "locked";
            _clearLockedState();
            itemsChanged();
            _notifyLauncherUpdate();
            return;
        }

        if (msg.action === "database-unlocked") {
            Qt.callLater(() => root.refreshEntries(false));
            return;
        }

        if (_handshaking && msg.action === "change-public-keys") {
            requestTimeoutTimer.stop();
            _handshaking = false;
            const expectedHsNonce = _handshakeNonce ? nacl.incrementNonce(_handshakeNonce) : null;
            _handshakeNonce = null;
            if (msg.errorCode || msg.error || msg.success !== "true" || !msg.publicKey) {
                _failAllRequests(msg.errorCode || "HANDSHAKE_FAILED", msg.error || "change-public-keys failed");
                _disconnectSocket();
                return;
            }
            if (msg.clientID && msg.clientID !== _clientId) {
                _failAllRequests("HANDSHAKE_FAILED", "clientID mismatch in change-public-keys response");
                _disconnectSocket();
                return;
            }
            try {
                const respHsNonce = nacl.decodeBase64(msg.nonce || "");
                if (!expectedHsNonce || respHsNonce.length !== 24 || !nacl.bytesEqual(respHsNonce, expectedHsNonce)) {
                    throw new Error("unexpected handshake response nonce");
                }
                const pub = nacl.decodeBase64(msg.publicKey);
                if (pub.length !== 32) {
                    throw new Error("invalid server publicKey length");
                }
                _serverPublicKey = pub;
                _serverVersion = String(msg.version || "");
                _socketReady = true;
                _pumpQueue();
            } catch (e) {
                _failAllRequests("HANDSHAKE_FAILED", String(e));
                _disconnectSocket();
            }
            return;
        }

        if (!_inflightReq)
            return;
        if (msg.action && msg.action !== _inflightReq.action)
            return;

        requestTimeoutTimer.stop();
        const req = _inflightReq;
        _inflightReq = null;

        if (!msg.message) {
            if (msg.errorCode || msg.error) {
                req.callback({ code: String(msg.errorCode || "ERROR"), message: msg.error || "KeePassXC error" }, null);
            } else {
                req.callback({ code: "EMPTY", message: "Empty response for " + req.action }, null);
            }
            _pumpQueue();
            return;
        }

        try {
            const respNonce = nacl.decodeBase64(msg.nonce || "");
            const cipherBytes = nacl.decodeBase64(msg.message);
            if (respNonce.length !== 24) {
                throw new Error("invalid response nonce");
            }
            if (!req.sentNonce || !nacl.bytesEqual(respNonce, nacl.incrementNonce(req.sentNonce))) {
                throw new Error("unexpected response nonce");
            }
            const plainBytes = nacl.boxOpen(cipherBytes, respNonce, _serverPublicKey, _sessionKeyPair.secretKey);
            if (!plainBytes) {
                throw new Error("failed to decrypt KeePassXC response");
            }
            const inner = JSON.parse(nacl.decodeUTF8(plainBytes));
            if (inner.errorCode || inner.error) {
                req.callback({ code: String(inner.errorCode || "ERROR"), message: inner.error || "KeePassXC error" }, null);
            } else {
                req.callback(null, inner);
            }
        } catch (e) {
            req.callback({ code: "DECRYPT_ERROR", message: String(e) }, null);
        }
        _pumpQueue();
    }

    function _sendEncrypted(action, payload, triggerUnlock, timeoutMs, callback) {
        _requestQueue.push({
            action: action,
            payload: payload || ({}),
            triggerUnlock: Boolean(triggerUnlock),
            timeoutMs: timeoutMs || 8000,
            callback: callback
        });

        if (_socketReady && kpxcSocket.connected) {
            _pumpQueue();
            return;
        }
        if (_handshaking || kpxcSocket.connected) {
            return;
        }

        _probeSocketPath(sockPath => {
            if (!sockPath) {
                _failAllRequests("NOT_RUNNING", "KeePassXC BrowserServer socket not found");
                return;
            }
            if (kpxcSocket.connected) {
                _pumpQueue();
                return;
            }
            _activeSocketPath = sockPath;
            kpxcSocket.path = sockPath;
            kpxcSocket.connected = true;
        });
    }

    function _pumpQueue() {
        if (!_socketReady || !kpxcSocket.connected || _inflightReq !== null || _requestQueue.length === 0)
            return;

        const req = _requestQueue.shift();
        _inflightReq = req;

        const inner = Object.assign({}, req.payload);
        inner.action = req.action;

        const reqNonce = nacl.randomBytes(24);
        req.sentNonce = reqNonce;
        const plainBytes = nacl.encodeUTF8(JSON.stringify(inner));
        const cipherBytes = nacl.box(plainBytes, reqNonce, _serverPublicKey, _sessionKeyPair.secretKey);

        const outer = {
            action: req.action,
            message: nacl.encodeBase64(cipherBytes),
            nonce: nacl.encodeBase64(reqNonce),
            clientID: _clientId
        };
        if (req.triggerUnlock) {
            outer.triggerUnlock = "true";
        }

        requestTimeoutTimer.interval = req.triggerUnlock ? Math.max(req.timeoutMs, 65000) : req.timeoutMs;
        requestTimeoutTimer.restart();

        if (!_sendRaw(outer)) {
            requestTimeoutTimer.stop();
            _inflightReq = null;
            if (typeof req.callback === "function") {
                req.callback({ code: "NOT_RUNNING", message: "Socket not connected" }, null);
            }
            _pumpQueue();
        }
    }

    // --- High-level KeePassXC Operations ---

    function refreshEntries(unlock) {
        if (_loading && !unlock)
            return;
        _loading = true;

        _sendEncrypted("get-databasehash", {}, Boolean(unlock), unlock ? 65000 : 8000, (err, hashResp) => {
            if (err) {
                root._loading = false;
                if (err.code === "NOT_RUNNING") {
                    root._status = "not_running";
                } else if (err.code === "1" || err.code === "5") {
                    root._status = "locked";
                } else {
                    root._status = "error";
                    root._errorMessage = err.message || "Failed to query KeePassXC";
                }
                root._entries = [];
                root.itemsChanged();
                root._notifyLauncherUpdate();
                return;
            }

            const dbHash = hashResp.hash || "";
            root._currentDbHash = dbHash;
            const assoc = root._associations[dbHash];
            if (!assoc || !assoc.id || !assoc.idKey) {
                root._loading = false;
                root._status = "unassociated";
                root._entries = [];
                root.itemsChanged();
                root._notifyLauncherUpdate();
                return;
            }

            root._sendEncrypted("test-associate", { id: assoc.id, key: assoc.idKey }, false, 8000, (tErr, testResp) => {
                if (tErr || !testResp || testResp.success !== "true") {
                    root._loading = false;
                    root._status = (tErr && tErr.code === "1") ? "locked" : "unassociated";
                    root._entries = [];
                    root.itemsChanged();
                    root._notifyLauncherUpdate();
                    return;
                }

                root._sendEncrypted("get-database-entries", {}, false, 15000, (eErr, entriesResp) => {
                    root._loading = false;

                    if (eErr && eErr.code === "19") {
                        root._status = "ok";
                        root._restrictedMode = true;
                        root._restrictedWarning = "Limited access mode: some entries cannot be found unless 'Allow limited access to all entries in connected databases' is enabled in KeePassXC (Tools → Settings → Browser Integration → Advanced).";
                        if (!root._warnedRestrictedMode) {
                            root._warnedRestrictedMode = true;
                            root._showWarning("Dux KeePassXC", root._restrictedWarning);
                        }
                        root._entries = root._cachedEntriesForDb(dbHash);
                        root.itemsChanged();
                        root._notifyLauncherUpdate();
                        root._loadGroupsInBackground();
                        return;
                    }

                    if (eErr) {
                        root._status = (eErr.code === "1") ? "locked" : "error";
                        root._errorMessage = eErr.message || "";
                        root._entries = [];
                        root.itemsChanged();
                        root._notifyLauncherUpdate();
                        return;
                    }

                    root._status = "ok";
                    root._restrictedMode = false;
                    root._restrictedWarning = "";
                    const rawList = Array.isArray(entriesResp.entries) ? entriesResp.entries : [];
                    const dbMeta = root._metaCache[dbHash] || ({});
                    const normalized = [];
                    for (let i = 0; i < rawList.length; i++) {
                        const raw = rawList[i];
                        if (!raw || !raw.uuid)
                            continue;
                        const cached = dbMeta[raw.uuid] || ({});
                        normalized.push({
                            uuid: raw.uuid,
                            title: raw.title || raw.name || "",
                            login: raw.login || cached.login || "",
                            url: raw.url || raw.submitUrl || "",
                            group: raw.group || cached.group || ""
                        });
                    }
                    root._entries = normalized;
                    root.itemsChanged();
                    root._notifyLauncherUpdate();
                });
            });
        });
    }

    function _loadGroupsInBackground() {
        _sendEncrypted("get-database-groups", {}, false, 8000, (err, resp) => {
            if (!err && resp && resp.groups) {
                root._groupPaths = nacl.flattenGroupPaths(resp.groups);
            }
        });
    }

    function _runRestrictedSearch(query) {
        if (!query || query.length < 2)
            return;
        const dbHash = _currentDbHash;
        const assoc = _associations[dbHash];
        if (!dbHash || !assoc)
            return;

        _lastSearchedQuery = query;
        const candidates = nacl.buildSearchCandidates(query, _groupPaths);
        if (candidates.length === 0)
            return;

        const discovered = [];
        const seen = ({});

        function step(idx) {
            if (idx >= candidates.length) {
                if (discovered.length > 0) {
                    root._mergeDiscoveredEntries(dbHash, discovered);
                }
                return;
            }
            root._sendEncrypted("get-logins", {
                url: candidates[idx],
                keys: [{ id: assoc.id, key: assoc.idKey }]
            }, false, 65000, (err, resp) => {
                if (!err && resp && Array.isArray(resp.entries)) {
                    for (let i = 0; i < resp.entries.length; i++) {
                        const raw = resp.entries[i];
                        if (!raw || !raw.uuid)
                            continue;
                        if (seen[raw.uuid])
                            continue;
                        seen[raw.uuid] = true;
                        discovered.push({
                            uuid: raw.uuid,
                            title: raw.name || raw.title || "",
                            login: raw.login || "",
                            url: raw.url || raw.submitUrl || "",
                            group: raw.group || ""
                        });
                    }
                }
                step(idx + 1);
            });
        }
        step(0);
    }

    function _mergeDiscoveredEntries(dbHash, incomingList) {
        if (!incomingList || incomingList.length === 0)
            return;

        const merged = _entries.slice();
        const byUuid = ({});
        for (let i = 0; i < merged.length; i++) {
            byUuid[merged[i].uuid] = i;
        }

        let changed = false;
        for (let j = 0; j < incomingList.length; j++) {
            const inc = incomingList[j];
            if (!inc || !inc.uuid)
                continue;
            _updateMetaCacheEntry(dbHash, inc);
            if (byUuid[inc.uuid] !== undefined) {
                const idx = byUuid[inc.uuid];
                const cur = Object.assign({}, merged[idx]);
                let itemChanged = false;
                if (inc.title && !cur.title) { cur.title = inc.title; itemChanged = true; }
                if (inc.login && !cur.login) { cur.login = inc.login; itemChanged = true; }
                if (inc.url && !cur.url) { cur.url = inc.url; itemChanged = true; }
                if (inc.group && !cur.group) { cur.group = inc.group; itemChanged = true; }
                if (itemChanged) {
                    merged[idx] = cur;
                    changed = true;
                }
            } else {
                byUuid[inc.uuid] = merged.length;
                merged.push(inc);
                changed = true;
            }
        }

        if (changed) {
            _entries = merged;
            itemsChanged();
            _notifyLauncherUpdate();
        }
    }

    function associateDatabase() {
        _seedEntropy(seededOk => {
            if (!seededOk) {
                root._showError("Dux KeePassXC", "Failed to read OS entropy before key generation");
                return;
            }
            _sendEncrypted("get-databasehash", {}, true, 65000, (err, hashResp) => {
                if (err) {
                    root._showError("Dux KeePassXC", err.message || "Failed to unlock KeePassXC");
                    return;
                }
                const dbHash = hashResp.hash || "";
                const idKeyPair = nacl.boxKeyPair();
                const idKey = nacl.encodeBase64(idKeyPair.publicKey);
                const sessionPub = nacl.encodeBase64(root._sessionKeyPair.publicKey);

                root._sendEncrypted("associate", { key: sessionPub, idKey: idKey }, false, 65000, (aErr, assocResp) => {
                    if (aErr || !assocResp || assocResp.success !== "true" || !assocResp.id) {
                        const msg = (aErr && aErr.message) || "Association failed or cancelled";
                        root._errorMessage = msg;
                        root._showError("Dux KeePassXC", msg);
                        return;
                    }
                    const finalHash = assocResp.hash || dbHash;
                    root._saveAssociation(finalHash, assocResp.id, idKey, () => {
                        root._showInfo("Dux KeePassXC", "Associated with KeePassXC database");
                        root.refreshEntries(false);
                    });
                });
            });
        });
    }

    function fixConfig() {
        const script = [
            'umask 077',
            'ini="${XDG_CONFIG_HOME:-$HOME/.config}/keepassxc/keepassxc.ini"',
            'dir=$(dirname "$ini")',
            'mkdir -p "$dir" && chmod 700 "$dir" || exit 1',
            'if [ ! -f "$ini" ]; then',
            '  tmp=$(mktemp "$dir/.keepassxc.ini.XXXXXX") || exit 1',
            '  if printf "[Browser]\\nEnabled=true\\nAllowGetDatabaseEntriesRequest=true\\n" > "$tmp" && chmod 600 "$tmp" && mv "$tmp" "$ini"; then',
            '    exit 0',
            '  else',
            '    rm -f "$tmp"',
            '    exit 1',
            '  fi',
            'fi',
            'tmp=$(mktemp "$dir/.keepassxc.ini.XXXXXX") || exit 1',
            'awk \'',
            '  BEGIN { in_b=0; saw_b=0; updated=0 }',
            '  /^\\[/{',
            '    if (in_b && !updated) { print "AllowGetDatabaseEntriesRequest=true"; updated=1 }',
            '    in_b = (tolower($0) == "[browser]");',
            '    if (in_b) saw_b = 1;',
            '    print; next',
            '  }',
            '  in_b && tolower($0) ~ /^[[:space:]]*allowgetdatabaseentriesrequest[[:space:]]*=/ {',
            '    print "AllowGetDatabaseEntriesRequest=true"; updated=1; next',
            '  }',
            '  { print }',
            '  END {',
            '    if (in_b && !updated) { print "AllowGetDatabaseEntriesRequest=true"; updated=1 }',
            '    if (!saw_b) { print ""; print "[Browser]"; print "Enabled=true"; print "AllowGetDatabaseEntriesRequest=true" }',
            '  }',
            '\' "$ini" > "$tmp" && chmod 600 "$tmp" && mv "$tmp" "$ini" || { rm -f "$tmp"; exit 1; }'
        ].join("\n");

        _runProcess(["sh", "-c", script], null, (exitCode, outText, errText) => {
            if (exitCode === 0) {
                root._showInfo("Dux KeePassXC", "Enabled entry listing in keepassxc.ini; restart KeePassXC if already open");
                Qt.callLater(() => root.refreshEntries(false));
            } else {
                root._showError("Dux KeePassXC", (errText || "").trim() || "Failed to update keepassxc.ini");
            }
        });
    }

    function lockDatabase() {
        _sendEncrypted("lock-database", {}, false, 8000, (err) => {
            if (err) {
                root._showError("Dux KeePassXC", err.message || "Failed to lock KeePassXC");
                return;
            }
            root._showInfo("Dux KeePassXC", "KeePassXC database locked");
            root._status = "locked";
            root._clearLockedState();
            root.itemsChanged();
            root._notifyLauncherUpdate();
        });
    }

    function _isVulnerableToEmptyUrlCrash() {
        return guardEmptyUrlCrash && !_restrictedMode && nacl.isEmptyUrlCrashVersion(_serverVersion);
    }

    function _fetchEntryDetail(uuid, callback) {
        const dbHash = _currentDbHash;
        const assoc = _associations[dbHash];
        if (!uuid || !dbHash || !assoc) {
            callback({ code: "UNASSOCIATED", message: "Database is not associated" }, null);
            return;
        }
        const known = _findEntryByUuid(uuid);
        if (_isVulnerableToEmptyUrlCrash() && known && !(known.url || "").trim()) {
            callback({
                code: "EMPTY_URL_BUG",
                message: "KeePassXC " + _serverVersion + " crashes on entries with no URL (upstream bug #13865). Add any URL (e.g. https://local.invalid) to \"" + (known.title || "this entry") + "\" in KeePassXC, or upgrade KeePassXC when 2.8.1 is released."
            }, null);
            return;
        }
        _sendEncrypted("get-logins", {
            url: "keepassxc://by-uuid/" + uuid,
            keys: [{ id: assoc.id, key: assoc.idKey }]
        }, false, 65000, (err, resp) => {
            if (err || !resp || resp.success !== "true" || !Array.isArray(resp.entries) || resp.entries.length === 0) {
                callback(err || { code: "NOT_FOUND", message: "Entry not found" }, null);
                return;
            }
            let matched = resp.entries[0];
            for (let i = 0; i < resp.entries.length; i++) {
                if (resp.entries[i] && resp.entries[i].uuid && resp.entries[i].uuid.toLowerCase() === uuid.toLowerCase()) {
                    matched = resp.entries[i];
                    break;
                }
            }
            const summary = {
                uuid: matched.uuid || uuid,
                title: matched.name || matched.title || "",
                login: matched.login || "",
                url: matched.url || matched.submitUrl || "",
                group: matched.group || ""
            };
            root._updateMetaCacheEntry(dbHash, summary);
            root._enrichEntryMetadata(summary.uuid, summary.login, summary.group);
            root._cacheEntryFields(summary.uuid, matched);
            callback(null, matched);
        });
    }

    function _findEntryByUuid(uuid) {
        if (!uuid)
            return null;
        for (let i = 0; i < _entries.length; i++) {
            if (_entries[i] && _entries[i].uuid === uuid)
                return _entries[i];
        }
        return null;
    }

    function _cacheEntryFields(uuid, matched) {
        if (!uuid || !matched)
            return;
        const fields = [];
        if (matched.password)
            fields.push("password");
        if (matched.login)
            fields.push("username");
        if (matched.totp)
            fields.push("totp");
        if (matched.url || matched.submitUrl)
            fields.push("url");
        if (Array.isArray(matched.stringFields)) {
            for (let i = 0; i < matched.stringFields.length; i++) {
                const obj = matched.stringFields[i];
                if (!obj || typeof obj !== "object")
                    continue;
                const keys = Object.keys(obj);
                for (let j = 0; j < keys.length; j++) {
                    const rawKey = keys[j];
                    const displayKey = rawKey.indexOf("KPH: ") === 0 ? rawKey.substring(5) : rawKey;
                    if (displayKey)
                        fields.push("field:" + displayKey);
                }
            }
        }
        const cache = Object.assign({}, _fieldsCache);
        cache[uuid] = fields;
        _fieldsCache = cache;
    }

    function loadFields(uuid) {
        if (!uuid || _fieldsCache[uuid] || _fieldsPending[uuid])
            return;
        const pending = Object.assign({}, _fieldsPending);
        pending[uuid] = true;
        _fieldsPending = pending;

        _fetchEntryDetail(uuid, (err, matched) => {
            const nextPending = Object.assign({}, root._fieldsPending);
            delete nextPending[uuid];
            root._fieldsPending = nextPending;

            if (err || !matched) {
                root._showError("Dux KeePassXC", (err && err.message) || "Failed to load custom fields");
                return;
            }
            root.itemsChanged();
            root._notifyLauncherUpdate();
        });
    }

    function _resolveFieldValue(matched, field, callback) {
        if (field === "password") {
            if (!matched.password) {
                callback("Entry has no password", null);
                return;
            }
            callback(null, matched.password);
            return;
        }
        if (field === "username" || field === "login") {
            if (!matched.login) {
                callback("Entry has no username", null);
                return;
            }
            callback(null, matched.login);
            return;
        }
        if (field === "url") {
            const u = matched.url || matched.submitUrl || "";
            if (!u) {
                callback("Entry has no URL", null);
                return;
            }
            callback(null, u);
            return;
        }
        if (field === "totp") {
            if (matched.totp) {
                callback(null, matched.totp);
                return;
            }
            _sendEncrypted("get-totp", { uuid: matched.uuid }, false, 8000, (tErr, tResp) => {
                if (tErr || !tResp || !tResp.totp) {
                    callback((tErr && tErr.message) || "Entry has no TOTP configured", null);
                    return;
                }
                callback(null, tResp.totp);
            });
            return;
        }

        const target = field.indexOf("field:") === 0 ? field.substring(6) : field;
        if (Array.isArray(matched.stringFields)) {
            for (let i = 0; i < matched.stringFields.length; i++) {
                const obj = matched.stringFields[i];
                if (!obj || typeof obj !== "object")
                    continue;
                const keys = Object.keys(obj);
                for (let j = 0; j < keys.length; j++) {
                    const rk = keys[j];
                    const dk = rk.indexOf("KPH: ") === 0 ? rk.substring(5) : rk;
                    if (dk === target || rk === target) {
                        callback(null, obj[rk] || "");
                        return;
                    }
                }
            }
        }
        callback("Custom field not found: " + target, null);
    }

    // --- Clipboard, Paste, and Auto-Type ---

    function _copySecret(secret, seconds, isPasteOnce, done) {
        const clean = secret.replace(/\n$/, "");
        const script = isPasteOnce ? [
            'secret=$(cat)',
            'if command -v wl-copy >/dev/null 2>&1; then',
            '  printf "%s" "$secret" | wl-copy --sensitive --trim-newline --paste-once >/dev/null 2>&1',
            'elif command -v dms >/dev/null 2>&1; then',
            '  printf "%s" "$secret" | setsid dms clipboard copy --paste-once >/dev/null 2>&1 &',
            'else',
            '  exit 1',
            'fi'
        ].join("\n") : [
            'secret=$(cat)',
            'if command -v wl-copy >/dev/null 2>&1; then',
            '  printf "%s" "$secret" | wl-copy --sensitive --trim-newline >/dev/null 2>&1',
            '  clip_backend="wl"',
            'elif command -v dms >/dev/null 2>&1; then',
            '  printf "%s" "$secret" | setsid dms clipboard copy >/dev/null 2>&1 &',
            '  clip_backend="dms"',
            'else',
            '  exit 1',
            'fi',
            'secs="$1"',
            'if [ "$secs" -gt 0 ] 2>/dev/null && command -v sha256sum >/dev/null 2>&1; then',
            '  salt=$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d " \\n")',
            '  [ -n "$salt" ] || salt="$$"',
            '  expected=$( { printf "%s:" "$salt"; printf "%s" "$secret"; } | sha256sum | cut -d" " -f1 )',
            '  if [ "$clip_backend" = "wl" ] && command -v wl-paste >/dev/null 2>&1; then',
            '    printf "%s %s\\n" "$salt" "$expected" | setsid sh -c \'IFS=" " read -r salt expected || exit 0; exec </dev/null; sleep "$1"; cur=$( { printf "%s:" "$salt"; wl-paste -n 2>/dev/null; } | sha256sum | cut -d" " -f1 ); [ "$cur" = "$expected" ] && wl-copy --clear >/dev/null 2>&1\' _ "$secs" >/dev/null 2>&1 &',
            '  elif [ "$clip_backend" = "dms" ]; then',
            '    printf "%s %s\\n" "$salt" "$expected" | setsid sh -c \'IFS=" " read -r salt expected || exit 0; exec </dev/null; sleep "$1"; cur=$( { printf "%s:" "$salt"; dms clipboard paste 2>/dev/null; } | sha256sum | cut -d" " -f1 ); [ "$cur" = "$expected" ] && printf "" | dms clipboard copy >/dev/null 2>&1\' _ "$secs" >/dev/null 2>&1 &',
            '  fi',
            'fi'
        ].join("\n");

        _runProcess(["sh", "-c", script, "_", String(seconds || 0)], clean, (exitCode) => {
            if (typeof done === "function")
                done(exitCode === 0);
        });
    }

    function _pasteSecret(secret, seconds, done) {
        const effectiveClear = seconds > 0 ? seconds : 5;
        _copySecret(secret, effectiveClear, false, ok => {
            if (!ok) {
                if (typeof done === "function")
                    done(false, "wl-copy / dms not available");
                return;
            }
            _runProcess(["sh", "-c", "sleep 0.15 && dms clipboard send-paste"], null, (exitCode, outText, errText) => {
                if (typeof done === "function")
                    done(exitCode === 0, (errText || "").trim());
            });
        });
    }

    function _autotypeSequence(username, password, seconds, done) {
        const user = username || "";
        const pass = password || "";
        const effectiveClear = seconds > 0 ? seconds : 15;
        _runProcess(["sh", "-c", "command -v wtype >/dev/null 2>&1"], null, (hasWtypeExit) => {
            if (hasWtypeExit === 0) {
                // Separate stdin writes via NUL-delimited python/awk-free shell or sequential Processes
                _runProcess(["sh", "-c", "sleep 0.2" + (user ? " && wtype -" : "")], user || null, (uExit) => {
                    if (uExit !== 0) {
                        done(false, false, "wtype username failed");
                        return;
                    }
                    _runProcess(["wtype", "-k", "Tab"], null, (tExit) => {
                        if (tExit !== 0) {
                            done(false, false, "wtype Tab failed");
                            return;
                        }
                        if (!pass) {
                            done(true, false, "Auto-typed credentials");
                            return;
                        }
                        _runProcess(["wtype", "-"], pass, (pExit) => {
                            done(pExit === 0, false, pExit === 0 ? "Auto-typed credentials" : "wtype password failed");
                        });
                    });
                });
                return;
            }

            // Fallback when wtype is not installed: paste username via DMS, then copy password to clipboard
            function copyPasswordStep() {
                if (!pass) {
                    done(true, true, "Pasted username");
                    return;
                }
                _copySecret(pass, effectiveClear, false, ok => {
                    done(ok, true, "Pasted username; password copied to clipboard (install wtype for Tab auto-type)");
                });
            }

            if (user) {
                _copySecret(user, 5, false, ok => {
                    if (!ok) {
                        done(false, true, "Failed to copy username");
                        return;
                    }
                    _runProcess(["sh", "-c", "sleep 0.2 && dms clipboard send-paste && sleep 0.15"], null, (pExit) => {
                        if (pExit !== 0) {
                            done(false, true, "dms clipboard send-paste failed");
                            return;
                        }
                        copyPasswordStep();
                    });
                });
            } else {
                copyPasswordStep();
            }
        });
    }

    function runAct(mode, uuid, field, entryTitle) {
        if (!uuid)
            return;
        _recordMru(uuid);
        const label = entryTitle || "entry";
        const targetField = field || "password";

        if (mode === "native-autotype") {
            _sendEncrypted("request-autotype", { search: uuid }, false, 65000, (err) => {
                if (err) {
                    root._showError("Dux KeePassXC", err.message || "KeePassXC auto-type failed");
                }
            });
            return;
        }

        function deliverValue(val) {
            if (mode === "copy") {
                _copySecret(val, clearSeconds, pasteOnce, ok => {
                    if (!ok) {
                        root._showError("Dux KeePassXC", "Failed to copy to clipboard");
                        return;
                    }
                    const fName = _humanizeField(targetField);
                    const suffix = clearSeconds > 0 && !pasteOnce
                        ? " (clears in " + clearSeconds + "s)"
                        : (pasteOnce ? " (paste once)" : "");
                    root._showInfo("Dux KeePassXC", "Copied " + fName + " for " + label + suffix);
                });
            } else if (mode === "paste") {
                _pasteSecret(val, clearSeconds, (ok, pasteErr) => {
                    if (!ok) {
                        root._showError("Dux KeePassXC", pasteErr || "Paste failed");
                    }
                });
            }
        }

        if ((mode === "copy" || mode === "paste") && targetField === "totp") {
            _sendEncrypted("get-totp", { uuid: uuid }, false, 8000, (tErr, tResp) => {
                if (tErr || !tResp || !tResp.totp) {
                    root._showError("Dux KeePassXC", (tErr && tErr.message) || "Entry has no TOTP configured");
                    return;
                }
                deliverValue(tResp.totp);
            });
            return;
        }

        if ((mode === "copy" || mode === "paste") && targetField === "url") {
            const knownEntry = _findEntryByUuid(uuid);
            if (knownEntry && knownEntry.url) {
                deliverValue(knownEntry.url);
                return;
            }
        }

        _fetchEntryDetail(uuid, (err, matched) => {
            if (err || !matched) {
                root._showError("Dux KeePassXC", (err && err.message) || "Failed to fetch entry");
                return;
            }

            if (mode === "autotype") {
                _autotypeSequence(matched.login || "", matched.password || "", clearSeconds, (ok, fallback, msg) => {
                    if (!ok) {
                        root._showError("Dux KeePassXC", msg || "Auto-type failed");
                    } else if (fallback && msg) {
                        root._showInfo("Dux KeePassXC", msg);
                    }
                });
                return;
            }

            _resolveFieldValue(matched, targetField, (valErr, val) => {
                if (valErr || val === null) {
                    root._showError("Dux KeePassXC", valErr || "Field unavailable");
                    return;
                }
                deliverValue(val);
            });
        });
    }

    function _copyFieldForPaste(uuid, targetField) {
        const effectiveClear = clearSeconds > 0 ? clearSeconds : 5;
        if (targetField === "totp") {
            _sendEncrypted("get-totp", { uuid: uuid }, false, 8000, (tErr, tResp) => {
                if (tErr || !tResp || !tResp.totp) {
                    root._showError("Dux KeePassXC", (tErr && tErr.message) || "Entry has no TOTP configured");
                    return;
                }
                _copySecret(tResp.totp, effectiveClear, false, ok => {
                    if (!ok)
                        root._showError("Dux KeePassXC", "Failed to copy for paste");
                });
            });
            return;
        }
        _fetchEntryDetail(uuid, (err, matched) => {
            if (err || !matched) {
                root._showError("Dux KeePassXC", (err && err.message) || "Failed to fetch entry");
                return;
            }
            _resolveFieldValue(matched, targetField, (valErr, val) => {
                if (valErr || val === null) {
                    root._showError("Dux KeePassXC", valErr || "Field unavailable");
                    return;
                }
                _copySecret(val, effectiveClear, false, ok => {
                    if (!ok)
                        root._showError("Dux KeePassXC", "Failed to copy for paste");
                });
            });
        });
    }

    // --- Non-Sensitive Metadata Cache & MRU ---

    function _cachedEntriesForDb(dbHash) {
        const dbMeta = _metaCache[dbHash];
        if (!dbMeta || typeof dbMeta !== "object")
            return [];
        const out = [];
        const keys = Object.keys(dbMeta);
        for (let i = 0; i < keys.length; i++) {
            const m = dbMeta[keys[i]];
            if (!m || !m.title)
                continue;
            out.push({
                uuid: m.uuid || keys[i],
                title: m.title,
                login: m.login || "",
                url: m.url || "",
                group: m.group || ""
            });
        }
        return out;
    }

    function _updateMetaCacheEntry(dbHash, summary) {
        if (!persistMetadataCache)
            return;
        if (!dbHash || !summary || !summary.uuid)
            return;
        if (!summary.title && !summary.login && !summary.url && !summary.group)
            return;

        const nextAll = Object.assign({}, _metaCache);
        const dbMap = Object.assign({}, nextAll[dbHash] || ({}));
        const prev = dbMap[summary.uuid] || ({});
        const nextEntry = {
            uuid: summary.uuid,
            title: summary.title || prev.title || "",
            login: summary.login || prev.login || "",
            url: summary.url || prev.url || "",
            group: summary.group || prev.group || ""
        };
        if (prev.title === nextEntry.title && prev.login === nextEntry.login && prev.url === nextEntry.url && prev.group === nextEntry.group)
            return;

        dbMap[summary.uuid] = nextEntry;
        nextAll[dbHash] = dbMap;
        _metaCache = nextAll;
        if (pluginService) {
            pluginService.savePluginState(pluginId, "metaCache", _metaCache);
        }
    }

    function _enrichEntryMetadata(uuid, login, group) {
        if (!uuid || (!login && !group))
            return;
        let changed = false;
        const nextEntries = _entries.slice();
        for (let i = 0; i < nextEntries.length; i++) {
            if (nextEntries[i].uuid === uuid) {
                const updated = Object.assign({}, nextEntries[i]);
                if (login && !updated.login) {
                    updated.login = login;
                    changed = true;
                }
                if (group && !updated.group) {
                    updated.group = group;
                    changed = true;
                }
                nextEntries[i] = updated;
                break;
            }
        }
        if (changed) {
            _entries = nextEntries;
        }
    }

    function _recordMru(uuid) {
        if (!uuid)
            return;
        const next = [uuid].concat(_mruIds.filter(id => id !== uuid));
        if (next.length > 25)
            next.length = 25;
        _mruIds = next;
        if (pluginService) {
            pluginService.savePluginState(pluginId, "mruIds", _mruIds);
        }
    }

    // --- DMS Launcher Plugin Contract ---

    function getCategories() {
        const seen = ({});
        const groups = [];
        for (let i = 0; i < _entries.length; i++) {
            const g = _entries[i].group;
            if (g && !seen[g]) {
                seen[g] = true;
                groups.push(g);
            }
        }
        if (groups.length === 0)
            return [];
        groups.sort((a, b) => a.localeCompare(b));
        const cats = [{ id: "all", name: "All" }];
        for (let i = 0; i < groups.length; i++) {
            cats.push({ id: groups[i], name: groups[i] });
        }
        return cats;
    }

    function setCategory(categoryId) {
        const next = (!categoryId || categoryId === "all") ? "all" : categoryId;
        if (_selectedCategory === next)
            return;
        _selectedCategory = next;
        itemsChanged();
    }

    function getItems(query) {
        const trimmed = query ? query.trim() : "";
        const lowerQuery = trimmed.toLowerCase();

        if (_status === "loading") {
            return [{
                name: "Connecting to KeePassXC...",
                icon: "material:hourglass_empty",
                comment: "Querying KeePassXC Browser Integration socket",
                action: "reload:",
                categories: ["Dux KeePassXC"]
            }];
        }

        if (_status === "not_running") {
            return [
                {
                    name: "KeePassXC is not running",
                    icon: "material:launch",
                    comment: "Press Enter to launch KeePassXC (enable Browser Integration in Settings)",
                    action: "launch:",
                    categories: ["Dux KeePassXC"]
                },
                {
                    name: "Reload Entries",
                    icon: "material:refresh",
                    comment: "Retry connecting to KeePassXC Browser Integration",
                    action: "reload:",
                    categories: ["Dux KeePassXC"]
                }
            ];
        }

        if (_status === "locked") {
            return [
                {
                    name: "KeePassXC Database is Locked",
                    icon: "material:lock_open",
                    comment: "Press Enter to prompt KeePassXC to unlock",
                    action: "unlock:",
                    categories: ["Dux KeePassXC"]
                },
                {
                    name: "Reload Entries",
                    icon: "material:refresh",
                    comment: "Retry after unlocking KeePassXC",
                    action: "reload:",
                    categories: ["Dux KeePassXC"]
                }
            ];
        }

        if (_status === "unassociated") {
            return [
                {
                    name: "Associate with KeePassXC",
                    icon: "material:link",
                    comment: "Press Enter to pair Dux KeePassXC with your open database",
                    action: "associate:",
                    categories: ["Dux KeePassXC"]
                },
                {
                    name: "Reload Entries",
                    icon: "material:refresh",
                    comment: "Retry checking KeePassXC association",
                    action: "reload:",
                    categories: ["Dux KeePassXC"]
                }
            ];
        }

        if (_status !== "ok") {
            return [{
                name: "KeePassXC Error",
                icon: "material:error_outline",
                comment: _errorMessage || "Press Enter to retry",
                action: "reload:",
                categories: ["Dux KeePassXC"]
            }];
        }

        if (_restrictedMode && trimmed.length >= 2 && trimmed !== _lastSearchedQuery) {
            _pendingSearchQuery = trimmed;
            searchDebounceTimer.restart();
        }

        const tokens = lowerQuery.length > 0 ? lowerQuery.split(/\s+/).filter(t => t.length > 0) : [];
        const scored = [];

        for (let i = 0; i < _entries.length; i++) {
            const entry = _entries[i];
            if (_selectedCategory !== "all" && (entry.group || "") !== _selectedCategory)
                continue;

            const title = entry.title || "";
            const login = entry.login || "";
            const url = entry.url || "";
            const group = entry.group || "";
            const haystack = (group + "/" + title + " " + login + " " + url).toLowerCase();

            let matched = true;
            for (let t = 0; t < tokens.length; t++) {
                if (!haystack.includes(tokens[t])) {
                    matched = false;
                    break;
                }
            }
            if (!matched)
                continue;

            const titleLower = title.toLowerCase();
            const mruIdx = _mruIds.indexOf(entry.uuid);
            let score = 0;
            if (mruIdx !== -1) {
                score += 10000 - mruIdx * 100;
            }
            if (tokens.length > 0) {
                if (titleLower === lowerQuery)
                    score += 5000;
                else if (titleLower.startsWith(lowerQuery))
                    score += 2500;
                else if (titleLower.includes(lowerQuery))
                    score += 1000;
            }

            const displayName = (group ? group + "/" : "") + title;
            let comment = login
                ? (url ? login + " • " + url : login)
                : (url || "KeePassXC Entry");
            if (_isVulnerableToEmptyUrlCrash() && !url.trim()) {
                const warnMsg = "No URL — KeePassXC " + _serverVersion + " crashes on fetch (bug #13865; add any URL)";
                comment = login ? (login + " • " + warnMsg) : warnMsg;
            }

            scored.push({
                score: score,
                sortName: displayName,
                item: {
                    name: displayName,
                    icon: "material:password",
                    comment: comment,
                    action: "entry:" + entry.uuid,
                    categories: ["Dux KeePassXC"],
                    _uuid: entry.uuid,
                    _title: title,
                    _login: login,
                    _url: url,
                    _group: group
                }
            });
        }

        scored.sort((a, b) => {
            if (a.score !== b.score)
                return b.score - a.score;
            return a.sortName.localeCompare(b.sortName);
        });

        const results = scored.slice(0, 47).map(s => s.item);
        const hasMatches = results.length > 0;

        const restrictedItem = {
            name: "Limited Access Mode: Some entries may not be found",
            icon: "material:warning",
            comment: "Type an exact title or domain/URL to search KeePassXC, or press Enter to enable full entry listing in keepassxc.ini",
            action: "fix-config:",
            categories: ["Dux KeePassXC"]
        };

        const reloadItem = {
            name: "Reload Entries",
            icon: "material:refresh",
            comment: "Refresh KeePassXC entry list",
            action: "reload:",
            categories: ["Dux KeePassXC"]
        };
        const lockItem = {
            name: "Lock Database",
            icon: "material:lock",
            comment: "Lock all open KeePassXC databases",
            action: "lock:",
            categories: ["Dux KeePassXC"]
        };

        if (_restrictedMode && hasMatches) {
            results.push(restrictedItem);
        }

        if (tokens.length === 0) {
            const insertAt = (_mruIds.length > 0 && hasMatches && _mruIds[0] === results[0]._uuid) ? 1 : 0;
            results.splice(insertAt, 0, reloadItem, lockItem);
        } else {
            if ("reload entries sync refresh".includes(lowerQuery))
                results.push(reloadItem);
            if ("lock database".includes(lowerQuery))
                results.push(lockItem);
        }

        if (_restrictedMode && !hasMatches) {
            results.unshift(restrictedItem);
        }

        const top = results.slice(0, 50);
        for (let i = 0; i < top.length; i++) {
            top[i]._preScored = 100000 - i;
        }
        return top;
    }

    function executeItem(item) {
        if (!item || !item.action)
            return;

        const sep = item.action.indexOf(":");
        const actionType = sep === -1 ? item.action : item.action.substring(0, sep);
        const actionData = sep === -1 ? "" : item.action.substring(sep + 1);

        switch (actionType) {
        case "launch":
            Quickshell.execDetached(["keepassxc"]);
            launchRefreshTimer.restart();
            break;
        case "unlock":
            refreshEntries(true);
            break;
        case "associate":
            associateDatabase();
            break;
        case "fix-config":
            fixConfig();
            break;
        case "reload":
            refreshEntries(false);
            break;
        case "lock":
            lockDatabase();
            break;
        case "entry":
            _executeDefaultEntryAction(item, actionData);
            break;
        }
    }

    function _executeDefaultEntryAction(item, uuid) {
        const def = defaultAction || "copy:password";
        if (def === "autotype") {
            runAct("autotype", uuid, "", item._title);
            return;
        }
        if (def === "native-autotype") {
            runAct("native-autotype", uuid, "", item._title);
            return;
        }
        const sep = def.indexOf(":");
        if (sep === -1) {
            runAct("copy", uuid, "password", item._title);
            return;
        }
        const mode = def.substring(0, sep);
        const field = def.substring(sep + 1) || "password";
        runAct(mode, uuid, field, item._title);
    }

    function getPasteArgs(item) {
        if (!item || !item._uuid)
            return null;

        let targetField = "password";
        const def = defaultAction || "";
        if (def === "copy:username" || def === "paste:username")
            targetField = "username";
        else if (def === "copy:totp" || def === "paste:totp")
            targetField = "totp";

        _recordMru(item._uuid);
        _copyFieldForPaste(item._uuid, targetField);
        return ["sh", "-c", "sleep 0.12"];
    }

    function getContextMenuActions(item) {
        if (!item || !item._uuid)
            return [];

        const uuid = item._uuid;
        const title = item._title || "";
        const cached = _fieldsCache[uuid] || [];

        const actions = [
            {
                icon: "content_copy",
                text: "Copy Password",
                closeLauncher: true,
                action: () => runAct("copy", uuid, "password", title)
            },
            {
                icon: "content_paste",
                text: "Paste Password",
                closeLauncher: true,
                action: () => runAct("paste", uuid, "password", title)
            },
            {
                icon: "person",
                text: "Copy Username",
                closeLauncher: true,
                action: () => runAct("copy", uuid, "username", title)
            },
            {
                icon: "keyboard",
                text: "Paste Username",
                closeLauncher: true,
                action: () => runAct("paste", uuid, "username", title)
            },
            {
                icon: "pin",
                text: "Copy TOTP",
                closeLauncher: true,
                action: () => runAct("copy", uuid, "totp", title)
            },
            {
                icon: "dialpad",
                text: "Paste TOTP",
                closeLauncher: true,
                action: () => runAct("paste", uuid, "totp", title)
            }
        ];

        for (let i = 0; i < cached.length; i++) {
            const f = cached[i];
            if (f.indexOf("field:") !== 0)
                continue;
            const label = _humanizeField(f.substring(6));
            actions.push({
                icon: "content_copy",
                text: "Copy " + label,
                closeLauncher: true,
                action: (function(fieldKey) {
                    return () => runAct("copy", uuid, fieldKey, title);
                })(f)
            });
            actions.push({
                icon: "content_paste",
                text: "Paste " + label,
                closeLauncher: true,
                action: (function(fieldKey) {
                    return () => runAct("paste", uuid, fieldKey, title);
                })(f)
            });
        }

        if (item._url && item._url.length > 0) {
            actions.push({
                icon: "link",
                text: "Copy URL",
                closeLauncher: true,
                action: () => runAct("copy", uuid, "url", title)
            });
            if (nacl.isUrlSchemeAllowed(item._url, allowedUrlSchemes)) {
                actions.push({
                    icon: "open_in_new",
                    text: "Open URL",
                    closeLauncher: true,
                    action: () => {
                        if (nacl.isUrlSchemeAllowed(item._url, root.allowedUrlSchemes)) {
                            Qt.openUrlExternally(item._url);
                        }
                    }
                });
            }
        }

        actions.push({
            icon: "keyboard_tab",
            text: "Auto-Type (User + Tab + Pass)",
            closeLauncher: true,
            action: () => runAct("autotype", uuid, "", title)
        });
        actions.push({
            icon: "bolt",
            text: "KeePassXC Native Auto-Type",
            closeLauncher: true,
            action: () => runAct("native-autotype", uuid, "", title)
        });

        if (!_fieldsCache[uuid]) {
            actions.push({
                icon: "tune",
                text: "Load Custom Fields",
                closeLauncher: false,
                action: () => loadFields(uuid)
            });
        }

        return actions;
    }

    function _humanizeField(f) {
        if (!f)
            return "";
        const raw = f.indexOf("field:") === 0 ? f.substring(6) : f;
        const spaced = raw.replace(/_/g, " ");
        return spaced.charAt(0).toUpperCase() + spaced.slice(1);
    }

    property Timer launchRefreshTimer: Timer {
        interval: 2000
        repeat: false
        onTriggered: root.refreshEntries(false)
    }

    property Timer searchDebounceTimer: Timer {
        interval: 250
        repeat: false
        onTriggered: {
            const q = root._pendingSearchQuery;
            if (q && q.length >= 2 && q !== root._lastSearchedQuery) {
                root._runRestrictedSearch(q);
            }
        }
    }

    function _runProcess(cmd, stdinPayload, callback) {
        const proc = cmdProcessComponent.createObject(root, {
            command: cmd,
            stdinPayload: stdinPayload,
            stdinEnabled: (stdinPayload !== null && stdinPayload !== undefined),
            callback: callback
        });
        proc.running = true;
    }

    property Component cmdProcessComponent: Component {
        Process {
            id: cmdProc
            property var stdinPayload: null
            property var callback: null
            property string _stdoutText: ""
            property string _stderrText: ""
            property bool _stdoutDone: false
            property bool _stderrDone: false
            property bool _exited: false
            property int _exitCode: -1
            property bool _finished: false

            running: false

            onStarted: {
                if (stdinPayload !== null && stdinPayload !== undefined) {
                    write(String(stdinPayload));
                    stdinEnabled = false;
                }
            }

            stdout: StdioCollector {
                onStreamFinished: {
                    cmdProc._stdoutText = text || "";
                    cmdProc._stdoutDone = true;
                    cmdProc._maybeFinish();
                }
            }

            stderr: StdioCollector {
                onStreamFinished: {
                    cmdProc._stderrText = text || "";
                    cmdProc._stderrDone = true;
                    cmdProc._maybeFinish();
                }
            }

            onExited: exitCode => {
                cmdProc._exitCode = exitCode;
                cmdProc._exited = true;
                cmdProc._maybeFinish();
            }

            function _maybeFinish() {
                if (_finished || !_exited || !_stdoutDone || !_stderrDone)
                    return;
                _finished = true;
                const cb = callback;
                const code = _exitCode;
                const out = _stdoutText;
                const err = _stderrText;
                callback = null;
                stdinPayload = null;
                if (typeof cb === "function") {
                    cb(code, out, err);
                }
                cmdProc.destroy();
            }
        }
    }

    function _createNacl() {
        // Pure JS NaCl crypto_box (Curve25519 + XSalsa20 + Poly1305) + KeePassXC protocol helpers.
        // Zero external dependencies; inlined directly for hot-reload compatibility in DMS/QML.

        var _gf0 = new Float64Array(16);
        var _gf1 = new Float64Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        var _121665 = new Float64Array([0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        var _9 = new Uint8Array(32);
        _9[0] = 9;

        var _sigma = new Uint8Array([
            101, 120, 112, 97, 110, 100, 32, 51,
            50, 45, 98, 121, 116, 101, 32, 107
        ]);

        // Internal XSalsa20-based CSPRNG state; must be seeded with >= 32 bytes of OS entropy via seedEntropy().
        var _rngKey = new Uint8Array(32);
        var _rngNonce = new Uint8Array(24);
        var _entropySeeded = false;
        var _seededBytes = 0;

        function seedEntropy(bytesArray) {
            if (!bytesArray || !bytesArray.length)
                return;
            var mix = new Uint8Array(32);
            for (var i = 0; i < bytesArray.length; i++) {
                mix[i & 31] ^= (bytesArray[i] & 0xff);
            }
            var sub = new Uint8Array(32);
            var in16 = new Uint8Array(16);
            for (var k = 0; k < 16; k++)
                in16[k] = _rngNonce[k] ^ mix[k];
            _coreHsalsa20(sub, in16, _rngKey, _sigma);
            for (var m = 0; m < 32; m++) {
                _rngKey[m] = sub[m] ^ mix[m];
            }
            _rngNonce = incrementNonce(_rngNonce);
            _seededBytes += bytesArray.length;
            if (_seededBytes >= 32) {
                _entropySeeded = true;
            }
        }

        function isSeeded() {
            return _entropySeeded;
        }

        function randomBytes(n) {
            if (!_entropySeeded)
                throw new Error("CSPRNG not seeded with OS entropy");
            var out = new Uint8Array(n);
            var zeros = new Uint8Array(n);
            _streamXsalsa20Xor(out, 0, zeros, 0, n, _rngNonce, _rngKey);
            _rngNonce = incrementNonce(_rngNonce);
            // Re-key forward secrecy
            var nextKey = new Uint8Array(32);
            _streamXsalsa20Xor(nextKey, 0, _rngKey, 0, 32, _rngNonce, _rngKey);
            _rngKey = nextKey;
            _rngNonce = incrementNonce(_rngNonce);
            return out;
        }

        function bytesEqual(a, b) {
            if (!a || !b || a.length !== b.length)
                return false;
            var diff = 0;
            for (var i = 0; i < a.length; i++) {
                diff |= (a[i] ^ b[i]);
            }
            return diff === 0;
        }

        function isUrlSchemeAllowed(urlStr, allowedSchemesStr) {
            if (!urlStr || typeof urlStr !== "string")
                return false;
            var trimmed = urlStr.trim();
            if (!trimmed || /[\x00-\x1f\x7f]/.test(trimmed))
                return false;
            var schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
            if (!schemeMatch)
                return false;
            var scheme = schemeMatch[1].toLowerCase();
            var rawList = (typeof allowedSchemesStr === "string") ? allowedSchemesStr : "";
            var parts = rawList.split(/[\s,;]+/);
            for (var i = 0; i < parts.length; i++) {
                var token = parts[i].toLowerCase().replace(/:+$/, "");
                if (token && /^[a-z][a-z0-9+.-]*$/.test(token) && token === scheme)
                    return true;
            }
            return false;
        }

        function isEmptyUrlCrashVersion(versionStr) {
            if (!versionStr || typeof versionStr !== "string")
                return false;
            var m = versionStr.trim().match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
            if (!m)
                return false;
            var major = parseInt(m[1], 10);
            var minor = parseInt(m[2], 10);
            var patch = m[3] ? parseInt(m[3], 10) : 0;
            return major === 2 && (minor === 7 || (minor === 8 && patch === 0));
        }

        function incrementNonce(nonce) {
            var next = new Uint8Array(24);
            for (var i = 0; i < 24; i++) {
                next[i] = nonce[i] & 0xff;
            }
            for (var j = 0; j < 24; j++) {
                next[j] = (next[j] + 1) & 0xff;
                if (next[j] !== 0)
                    break;
            }
            return next;
        }

        function _L32(x, c) {
            return (x << c) | (x >>> (32 - c));
        }

        function _ld32(x, i) {
            var u = x[i + 3] & 0xff;
            u = (u << 8) | (x[i + 2] & 0xff);
            u = (u << 8) | (x[i + 1] & 0xff);
            return (u << 8) | (x[i] & 0xff);
        }

        function _st32(x, j, u) {
            for (var i = 0; i < 4; i++) {
                x[j + i] = u & 0xff;
                u >>>= 8;
            }
        }

        function _core(out, inArr, k, c, h) {
            var w = new Int32Array(16);
            var x = new Int32Array(16);
            var y = new Int32Array(16);
            var t = new Int32Array(4);
            var i, j, m;

            for (i = 0; i < 4; i++) {
                x[5 * i] = _ld32(c, 4 * i);
                x[1 + i] = _ld32(k, 4 * i);
                x[6 + i] = _ld32(inArr, 4 * i);
                x[11 + i] = _ld32(k, 16 + 4 * i);
            }

            for (i = 0; i < 16; i++)
                y[i] = x[i];

            for (i = 0; i < 20; i++) {
                for (j = 0; j < 4; j++) {
                    for (m = 0; m < 4; m++)
                        t[m] = x[(5 * j + 4 * m) % 16];
                    t[1] ^= _L32((t[0] + t[3]) | 0, 7);
                    t[2] ^= _L32((t[1] + t[0]) | 0, 9);
                    t[3] ^= _L32((t[2] + t[1]) | 0, 13);
                    t[0] ^= _L32((t[3] + t[2]) | 0, 18);
                    for (m = 0; m < 4; m++)
                        w[4 * j + ((j + m) % 4)] = t[m];
                }
                for (m = 0; m < 16; m++)
                    x[m] = w[m];
            }

            if (h) {
                for (i = 0; i < 16; i++)
                    x[i] = (x[i] + y[i]) | 0;
                for (i = 0; i < 4; i++) {
                    x[5 * i] = (x[5 * i] - _ld32(c, 4 * i)) | 0;
                    x[6 + i] = (x[6 + i] - _ld32(inArr, 4 * i)) | 0;
                }
                for (i = 0; i < 4; i++) {
                    _st32(out, 4 * i, x[5 * i]);
                    _st32(out, 16 + 4 * i, x[6 + i]);
                }
            } else {
                for (i = 0; i < 16; i++)
                    _st32(out, 4 * i, (x[i] + y[i]) | 0);
            }
        }

        function _coreSalsa20(out, inArr, k, c) {
            _core(out, inArr, k, c, false);
        }

        function _coreHsalsa20(out, inArr, k, c) {
            _core(out, inArr, k, c, true);
        }

        function _streamSalsa20Xor(c, cpos, m, mpos, b, n, k) {
            var z = new Uint8Array(16);
            var x = new Uint8Array(64);
            var u, i;
            if (!b)
                return 0;

            for (i = 0; i < 16; i++)
                z[i] = 0;
            for (i = 0; i < 8; i++)
                z[i] = n[i];

            while (b >= 64) {
                _coreSalsa20(x, z, k, _sigma);
                for (i = 0; i < 64; i++)
                    c[cpos + i] = (m ? m[mpos + i] : 0) ^ x[i];
                u = 1;
                for (i = 8; i < 16; i++) {
                    u = (u + (z[i] & 0xff)) | 0;
                    z[i] = u & 0xff;
                    u >>>= 8;
                }
                b -= 64;
                cpos += 64;
                if (m)
                    mpos += 64;
            }

            if (b > 0) {
                _coreSalsa20(x, z, k, _sigma);
                for (i = 0; i < b; i++)
                    c[cpos + i] = (m ? m[mpos + i] : 0) ^ x[i];
            }
            return 0;
        }

        function _streamXsalsa20Xor(c, cpos, m, mpos, b, n, k) {
            var s = new Uint8Array(32);
            _coreHsalsa20(s, n, k, _sigma);
            return _streamSalsa20Xor(c, cpos, m, mpos, b, n.subarray(16), s);
        }

        function _add1305(h, c) {
            var j;
            var u = 0;
            for (j = 0; j < 17; j++) {
                u = (u + ((h[j] + c[j]) | 0)) | 0;
                h[j] = u & 255;
                u >>>= 8;
            }
        }

        var _minusp = new Uint32Array([5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]);

        function _poly1305(out, outpos, m, mpos, n, k) {
            var s, i, j, u;
            var x = new Uint32Array(17);
            var r = new Uint32Array(17);
            var h = new Uint32Array(17);
            var c = new Uint32Array(17);
            var g = new Uint32Array(17);

            for (j = 0; j < 17; j++)
                r[j] = h[j] = 0;
            for (j = 0; j < 16; j++)
                r[j] = k[j];

            r[3] &= 15;
            r[4] &= 252;
            r[7] &= 15;
            r[8] &= 252;
            r[11] &= 15;
            r[12] &= 252;
            r[15] &= 15;

            while (n > 0) {
                for (j = 0; j < 17; j++)
                    c[j] = 0;
                for (j = 0; (j < 16) && (j < n); ++j)
                    c[j] = m[mpos + j];
                c[j] = 1;
                mpos += j;
                n -= j;
                _add1305(h, c);
                for (i = 0; i < 17; i++) {
                    x[i] = 0;
                    for (j = 0; j < 17; j++) {
                        x[i] = (x[i] + (h[j] * ((j <= i) ? r[i - j] : ((320 * r[i + 17 - j]) | 0))) | 0) | 0;
                    }
                }
                for (i = 0; i < 17; i++)
                    h[i] = x[i];
                u = 0;
                for (j = 0; j < 16; j++) {
                    u = (u + h[j]) | 0;
                    h[j] = u & 255;
                    u >>>= 8;
                }
                u = (u + h[16]) | 0;
                h[16] = u & 3;
                u = (5 * (u >>> 2)) | 0;
                for (j = 0; j < 16; j++) {
                    u = (u + h[j]) | 0;
                    h[j] = u & 255;
                    u >>>= 8;
                }
                u = (u + h[16]) | 0;
                h[16] = u;
            }

            for (j = 0; j < 17; j++)
                g[j] = h[j];
            _add1305(h, _minusp);
            s = (-(h[16] >>> 7) | 0);
            for (j = 0; j < 17; j++)
                h[j] ^= s & (g[j] ^ h[j]);

            for (j = 0; j < 16; j++)
                c[j] = k[j + 16];
            c[16] = 0;
            _add1305(h, c);
            for (j = 0; j < 16; j++)
                out[outpos + j] = h[j];
        }

        function _vn(x, xi, y, yi, n) {
            var d = 0;
            for (var i = 0; i < n; i++)
                d |= x[xi + i] ^ y[yi + i];
            return (1 & ((d - 1) >>> 8)) - 1;
        }

        function _verify16(x, xi, y, yi) {
            return _vn(x, xi, y, yi, 16);
        }

        function _set25519(r, a) {
            for (var i = 0; i < 16; i++)
                r[i] = a[i] | 0;
        }

        function _car25519(o) {
            var c;
            for (var i = 0; i < 16; i++) {
                o[i] += 65536;
                c = Math.floor(o[i] / 65536);
                o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i === 15 ? 1 : 0);
                o[i] -= (c * 65536);
            }
        }

        function _sel25519(p, q, b) {
            var t;
            var c = ~(b - 1);
            for (var i = 0; i < 16; i++) {
                t = c & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        function _pack25519(o, n) {
            var i, j, b;
            var m = new Float64Array(16);
            var t = new Float64Array(16);
            for (i = 0; i < 16; i++)
                t[i] = n[i];
            _car25519(t);
            _car25519(t);
            _car25519(t);
            for (j = 0; j < 2; j++) {
                m[0] = t[0] - 0xffed;
                for (i = 1; i < 15; i++) {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xffff;
                }
                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                b = (m[15] >> 16) & 1;
                m[14] &= 0xffff;
                _sel25519(t, m, 1 - b);
            }
            for (i = 0; i < 16; i++) {
                o[2 * i] = t[i] & 0xff;
                o[2 * i + 1] = t[i] >> 8;
            }
        }

        function _unpack25519(o, n) {
            for (var i = 0; i < 16; i++)
                o[i] = n[2 * i] + (n[2 * i + 1] << 8);
            o[15] &= 0x7fff;
        }

        function _A(o, a, b) {
            for (var i = 0; i < 16; i++)
                o[i] = a[i] + b[i];
        }

        function _Z(o, a, b) {
            for (var i = 0; i < 16; i++)
                o[i] = a[i] - b[i];
        }

        function _M(o, a, b) {
            var i, j;
            var t = new Float64Array(31);
            for (i = 0; i < 31; i++)
                t[i] = 0;
            for (i = 0; i < 16; i++) {
                for (j = 0; j < 16; j++)
                    t[i + j] += a[i] * b[j];
            }
            for (i = 0; i < 15; i++)
                t[i] += 38 * t[i + 16];
            for (i = 0; i < 16; i++)
                o[i] = t[i];
            _car25519(o);
            _car25519(o);
        }

        function _S(o, a) {
            _M(o, a, a);
        }

        function _inv25519(o, i) {
            var c = new Float64Array(16);
            var a;
            for (a = 0; a < 16; a++)
                c[a] = i[a];
            for (a = 253; a >= 0; a--) {
                _S(c, c);
                if (a !== 2 && a !== 4)
                    _M(c, c, i);
            }
            for (a = 0; a < 16; a++)
                o[a] = c[a];
        }

        function _scalarmult(q, n, p) {
            var z = new Uint8Array(32);
            var x = new Float64Array(80);
            var r, i;
            var a = new Float64Array(16);
            var b = new Float64Array(16);
            var c = new Float64Array(16);
            var d = new Float64Array(16);
            var e = new Float64Array(16);
            var f = new Float64Array(16);

            for (i = 0; i < 31; i++)
                z[i] = n[i];
            z[31] = (n[31] & 127) | 64;
            z[0] &= 248;
            _unpack25519(x, p);
            for (i = 0; i < 16; i++) {
                b[i] = x[i];
                d[i] = a[i] = c[i] = 0;
            }
            a[0] = d[0] = 1;
            for (i = 254; i >= 0; --i) {
                r = (z[i >>> 3] >>> (i & 7)) & 1;
                _sel25519(a, b, r);
                _sel25519(c, d, r);
                _A(e, a, c);
                _Z(a, a, c);
                _A(c, b, d);
                _Z(b, b, d);
                _S(d, e);
                _S(f, a);
                _M(a, c, a);
                _M(c, b, e);
                _A(e, a, c);
                _Z(a, a, c);
                _S(b, a);
                _Z(c, d, f);
                _M(a, c, _121665);
                _A(a, a, d);
                _M(c, c, a);
                _M(a, d, f);
                _M(d, b, x);
                _S(b, e);
                _sel25519(a, b, r);
                _sel25519(c, d, r);
            }
            for (i = 0; i < 16; i++) {
                x[i + 16] = a[i];
                x[i + 32] = c[i];
                x[i + 48] = b[i];
                x[i + 64] = d[i];
            }
            var x32 = x.subarray(32);
            var x16 = x.subarray(16);
            _inv25519(x32, x32);
            _M(x16, x16, x32);
            _pack25519(q, x16);
        }

        function _scalarmultBase(q, n) {
            _scalarmult(q, n, _9);
        }

        function _boxBeforenm(k, y, x) {
            var s = new Uint8Array(32);
            _scalarmult(s, x, y);
            _coreHsalsa20(k, _gf0, s, _sigma);
        }

        function _secretbox(c, m, d, n, k) {
            if (d < 32)
                return -1;
            _streamXsalsa20Xor(c, 0, m, 0, d, n, k);
            _poly1305(c, 16, c, 32, d - 32, c);
            for (var i = 0; i < 16; i++)
                c[i] = 0;
            return 0;
        }

        function _secretboxOpen(m, c, d, n, k) {
            if (d < 32)
                return -1;
            var otk = new Uint8Array(32);
            _streamXsalsa20Xor(otk, 0, null, 0, 32, n, k);
            var mac = new Uint8Array(16);
            _poly1305(mac, 0, c, 32, d - 32, otk);
            if (_verify16(c, 16, mac, 0) !== 0)
                return -1;
            _streamXsalsa20Xor(m, 0, c, 0, d, n, k);
            for (var i = 0; i < 32; i++)
                m[i] = 0;
            return 0;
        }

        function boxKeyPair() {
            var sk = randomBytes(32);
            var pk = new Uint8Array(32);
            _scalarmultBase(pk, sk);
            return { publicKey: pk, secretKey: sk };
        }

        function boxKeyPairFromSecretKey(secretKey) {
            if (!secretKey || secretKey.length !== 32)
                throw new Error("bad secret key size");
            var sk = new Uint8Array(secretKey);
            var pk = new Uint8Array(32);
            _scalarmultBase(pk, sk);
            return { publicKey: pk, secretKey: sk };
        }

        function box(msg, nonce, theirPublicKey, mySecretKey) {
            if (!nonce || nonce.length !== 24)
                throw new Error("bad nonce size");
            if (!theirPublicKey || theirPublicKey.length !== 32)
                throw new Error("bad public key size");
            if (!mySecretKey || mySecretKey.length !== 32)
                throw new Error("bad secret key size");

            var k = new Uint8Array(32);
            _boxBeforenm(k, theirPublicKey, mySecretKey);

            var m = new Uint8Array(32 + msg.length);
            var c = new Uint8Array(m.length);
            for (var i = 0; i < msg.length; i++)
                m[i + 32] = msg[i];
            _secretbox(c, m, m.length, nonce, k);
            return c.subarray(16);
        }

        function boxOpen(cipher, nonce, theirPublicKey, mySecretKey) {
            if (!nonce || nonce.length !== 24)
                throw new Error("bad nonce size");
            if (!theirPublicKey || theirPublicKey.length !== 32)
                throw new Error("bad public key size");
            if (!mySecretKey || mySecretKey.length !== 32)
                throw new Error("bad secret key size");
            if (!cipher || cipher.length < 16)
                return null;

            var k = new Uint8Array(32);
            _boxBeforenm(k, theirPublicKey, mySecretKey);

            var c = new Uint8Array(16 + cipher.length);
            var m = new Uint8Array(c.length);
            for (var i = 0; i < cipher.length; i++)
                c[i + 16] = cipher[i];
            if (_secretboxOpen(m, c, c.length, nonce, k) !== 0)
                return null;
            return m.subarray(32);
        }

        // Pure JS UTF-8 encode/decode

        function encodeUTF8(str) {
            var out = [];
            for (var i = 0; i < str.length; i++) {
                var c = str.charCodeAt(i);
                if (c < 0x80) {
                    out.push(c);
                } else if (c < 0x800) {
                    out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
                } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
                    var c2 = str.charCodeAt(++i);
                    var cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
                    out.push(
                        0xf0 | (cp >> 18),
                        0x80 | ((cp >> 12) & 0x3f),
                        0x80 | ((cp >> 6) & 0x3f),
                        0x80 | (cp & 0x3f)
                    );
                } else {
                    out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
                }
            }
            return new Uint8Array(out);
        }

        function decodeUTF8(arr) {
            var out = "";
            var i = 0;
            while (i < arr.length) {
                var b0 = arr[i++];
                if (b0 < 0x80) {
                    out += String.fromCharCode(b0);
                } else if ((b0 & 0xe0) === 0xc0 && i < arr.length) {
                    var b1 = arr[i++] & 0x3f;
                    out += String.fromCharCode(((b0 & 0x1f) << 6) | b1);
                } else if ((b0 & 0xf0) === 0xe0 && i + 1 < arr.length) {
                    var e1 = arr[i++] & 0x3f;
                    var e2 = arr[i++] & 0x3f;
                    out += String.fromCharCode(((b0 & 0x0f) << 12) | (e1 << 6) | e2);
                } else if ((b0 & 0xf8) === 0xf0 && i + 2 < arr.length) {
                    var f1 = arr[i++] & 0x3f;
                    var f2 = arr[i++] & 0x3f;
                    var f3 = arr[i++] & 0x3f;
                    var cp = ((b0 & 0x07) << 18) | (f1 << 12) | (f2 << 6) | f3;
                    cp -= 0x10000;
                    out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
                } else {
                    out += "\ufffd";
                }
            }
            return out;
        }

        // Pure JS Base64 encode/decode

        var _b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var _b64Lookup = (function() {
            var t = new Int16Array(256);
            for (var i = 0; i < 256; i++)
                t[i] = -1;
            for (var j = 0; j < _b64Chars.length; j++)
                t[_b64Chars.charCodeAt(j)] = j;
            return t;
        })();

        function encodeBase64(bytes) {
            var out = "";
            var len = bytes.length;
            for (var i = 0; i < len; i += 3) {
                var a = bytes[i];
                var hasB = (i + 1) < len;
                var hasC = (i + 2) < len;
                var b = hasB ? bytes[i + 1] : 0;
                var c = hasC ? bytes[i + 2] : 0;
                var n = (a << 16) | (b << 8) | c;
                out += _b64Chars[(n >> 18) & 63];
                out += _b64Chars[(n >> 12) & 63];
                out += hasB ? _b64Chars[(n >> 6) & 63] : "=";
                out += hasC ? _b64Chars[n & 63] : "=";
            }
            return out;
        }

        function decodeBase64(str) {
            var clean = "";
            for (var k = 0; k < str.length; k++) {
                var ch = str.charCodeAt(k);
                if (ch > 32)
                    clean += str.charAt(k);
            }
            if (clean.length % 4 !== 0)
                throw new Error("invalid base64 length");
            var pad = 0;
            if (clean.length > 0 && clean.charAt(clean.length - 1) === "=")
                pad++;
            if (clean.length > 1 && clean.charAt(clean.length - 2) === "=")
                pad++;
            var outLen = (clean.length / 4) * 3 - pad;
            var out = new Uint8Array(outLen);
            var p = 0;
            for (var i = 0; i < clean.length; i += 4) {
                var c0 = _b64Lookup[clean.charCodeAt(i)];
                var c1 = _b64Lookup[clean.charCodeAt(i + 1)];
                var c2 = clean.charAt(i + 2) === "=" ? 0 : _b64Lookup[clean.charCodeAt(i + 2)];
                var c3 = clean.charAt(i + 3) === "=" ? 0 : _b64Lookup[clean.charCodeAt(i + 3)];
                if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0)
                    throw new Error("invalid base64 character");
                var n = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
                if (p < outLen)
                    out[p++] = (n >> 16) & 0xff;
                if (p < outLen)
                    out[p++] = (n >> 8) & 0xff;
                if (p < outLen)
                    out[p++] = n & 0xff;
            }
            return out;
        }

        // KeePassXC protocol framing & search helpers

        function extractJsonObjects(bufferStr) {
            var objects = [];
            var len = bufferStr.length;
            var start = -1;
            var depth = 0;
            var inString = false;
            var escaped = false;
            var lastEnd = 0;

            for (var i = 0; i < len; i++) {
                var ch = bufferStr.charAt(i);
                if (start === -1) {
                    if (ch === "{") {
                        start = i;
                        depth = 1;
                        inString = false;
                        escaped = false;
                    }
                    continue;
                }

                if (inString) {
                    if (escaped) {
                        escaped = false;
                    } else if (ch === "\\") {
                        escaped = true;
                    } else if (ch === "\"") {
                        inString = false;
                    }
                    continue;
                }

                if (ch === "\"") {
                    inString = true;
                } else if (ch === "{") {
                    depth++;
                } else if (ch === "}") {
                    depth--;
                    if (depth === 0) {
                        var slice = bufferStr.substring(start, i + 1);
                        try {
                            objects.push(JSON.parse(slice));
                        } catch (e) {
                            // Ignore malformed frame and advance past it
                        }
                        lastEnd = i + 1;
                        start = -1;
                    }
                }
            }

            var rest = start !== -1 ? bufferStr.substring(start) : "";
            if (start === -1 && lastEnd > 0 && lastEnd < len) {
                // Trim only consumed prefix; keep any trailing non-brace whitespace empty
                var tail = bufferStr.substring(lastEnd);
                for (var j = 0; j < tail.length; j++) {
                    if (tail.charCodeAt(j) > 32) {
                        rest = tail.substring(j);
                        break;
                    }
                }
            }
            return { objects: objects, rest: rest };
        }

        function flattenGroupPaths(groupsPayload) {
            var topNodes = [];
            if (Array.isArray(groupsPayload)) {
                topNodes = groupsPayload;
            } else if (groupsPayload && Array.isArray(groupsPayload.groups)) {
                topNodes = groupsPayload.groups;
            }

            var rawPaths = [];
            function walk(nodes, prefix, isRootLevel) {
                for (var i = 0; i < nodes.length; i++) {
                    var node = nodes[i];
                    if (!node)
                        continue;
                    var name = typeof node.name === "string" ? node.name : "";
                    var children = Array.isArray(node.children) ? node.children : [];
                    if (!name) {
                        if (children.length > 0)
                            walk(children, prefix, isRootLevel);
                        continue;
                    }
                    var fullPath = prefix ? (prefix + "/" + name) : name;
                    rawPaths.push(fullPath);
                    if (isRootLevel) {
                        if (children.length > 0) {
                            walk(children, fullPath, false);
                            walk(children, "", false);
                        }
                    } else if (children.length > 0) {
                        walk(children, fullPath, false);
                    }
                }
            }
            walk(topNodes, "", true);

            var seen = {};
            var out = [];
            for (var k = 0; k < rawPaths.length; k++) {
                var p = rawPaths[k];
                if (!p || seen[p])
                    continue;
                seen[p] = true;
                out.push(p);
            }
            return out;
        }

        function buildSearchCandidates(query, groupPaths) {
            var trimmed = query ? query.trim() : "";
            if (!trimmed)
                return [];

            var candidates = [];
            var lower = trimmed.toLowerCase();
            if (lower.indexOf("http://") === 0 || lower.indexOf("https://") === 0 || lower.indexOf("keepassxc://") === 0) {
                candidates.push(trimmed);
            } else {
                candidates.push("keepassxc://by-path/" + trimmed);
                if (Array.isArray(groupPaths)) {
                    var count = 0;
                    for (var i = 0; i < groupPaths.length; i++) {
                        var g = groupPaths[i];
                        if (!g)
                            continue;
                        candidates.push("keepassxc://by-path/" + g + "/" + trimmed);
                        count++;
                        if (count >= 25)
                            break;
                    }
                }
                if (trimmed.indexOf(".") !== -1) {
                    candidates.push("https://" + trimmed);
                } else if (trimmed.indexOf("/") === -1) {
                    var tlds = [".com", ".org", ".net", ".io", ".dev"];
                    for (var j = 0; j < tlds.length; j++) {
                        candidates.push("https://" + trimmed + tlds[j]);
                    }
                }
            }

            var seen = {};
            var unique = [];
            for (var u = 0; u < candidates.length; u++) {
                var c = candidates[u];
                if (!c || seen[c])
                    continue;
                seen[c] = true;
                unique.push(c);
            }
            return unique;
        }

        return {
            encodeUTF8: encodeUTF8,
            decodeUTF8: decodeUTF8,
            encodeBase64: encodeBase64,
            decodeBase64: decodeBase64,
            seedEntropy: seedEntropy,
            isSeeded: isSeeded,
            randomBytes: randomBytes,
            incrementNonce: incrementNonce,
            bytesEqual: bytesEqual,
            isUrlSchemeAllowed: isUrlSchemeAllowed,
            isEmptyUrlCrashVersion: isEmptyUrlCrashVersion,
            boxKeyPair: boxKeyPair,
            boxKeyPairFromSecretKey: boxKeyPairFromSecretKey,
            box: box,
            boxOpen: boxOpen,
            extractJsonObjects: extractJsonObjects,
            flattenGroupPaths: flattenGroupPaths,
            buildSearchCandidates: buildSearchCandidates
        };
    }
}

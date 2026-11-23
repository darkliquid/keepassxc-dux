import QtQuick
import qs.Common
import qs.Widgets
import qs.Modules.Plugins

PluginSettings {
    id: root
    pluginId: "duxKeePassXC"

    StyledText {
        width: parent.width
        text: "Dux KeePassXC Settings"
        font.pixelSize: Theme.fontSizeLarge
        font.weight: Font.Bold
        color: Theme.surfaceText
    }

    StyledText {
        width: parent.width
        text: "Search and retrieve KeePassXC credentials via KeePassXC Browser Integration. Enable Browser Integration and Tools → Settings → Browser Integration → Advanced → 'Allow limited access to all entries in connected databases (ignores site access restrictions)' in KeePassXC. To skip per-entry confirmation popups on first access, either check 'Remember access to checked entries' or enable 'Never ask before accessing credentials' in Browser Integration → Advanced."
        font.pixelSize: Theme.fontSizeSmall
        color: Theme.surfaceVariantText
        wrapMode: Text.WordWrap
    }

    Rectangle {
        width: parent.width
        height: 1
        color: Theme.outline
        opacity: 0.3
    }

    ToggleSetting {
        id: noTriggerToggle
        settingKey: "noTrigger"
        label: "Always Active"
        description: value ? "Show KeePassXC entries without a trigger prefix" : "Use trigger prefix"
        defaultValue: false
        onValueChanged: {
            if (value)
                root.saveValue("trigger", "");
            else
                root.saveValue("trigger", triggerSetting.value || "[");
        }
    }

    StringSetting {
        id: triggerSetting
        visible: !noTriggerToggle.value
        settingKey: "trigger"
        label: "Trigger"
        description: "Prefix to activate KeePassXC search in the launcher (default: [)"
        placeholder: "["
        defaultValue: "["
    }

    SelectionSetting {
        settingKey: "defaultAction"
        label: "Default Enter Action"
        description: "Action executed when pressing Enter on an entry (Shift+Enter always pastes)"
        defaultValue: "copy:password"
        options: [
            { label: "Copy Password", value: "copy:password" },
            { label: "Paste Password", value: "paste:password" },
            { label: "Auto-type (User + Tab + Pass)", value: "autotype" },
            { label: "KeePassXC Native Auto-Type", value: "native-autotype" },
            { label: "Copy Username", value: "copy:username" },
            { label: "Paste Username", value: "paste:username" },
            { label: "Copy TOTP", value: "copy:totp" },
            { label: "Paste TOTP", value: "paste:totp" }
        ]
    }

    SelectionSetting {
        settingKey: "clearSeconds"
        label: "Clipboard Auto-Clear Timeout"
        description: "Automatically clear copied secrets from clipboard if unchanged"
        defaultValue: "15"
        options: [
            { label: "10 seconds", value: "10" },
            { label: "15 seconds", value: "15" },
            { label: "30 seconds", value: "30" },
            { label: "45 seconds", value: "45" },
            { label: "Never", value: "0" }
        ]
    }

    ToggleSetting {
        settingKey: "pasteOnce"
        label: "Paste Once (wl-copy --paste-once)"
        description: "Clear copied secret immediately after the first paste"
        defaultValue: false
    }

    SelectionSetting {
        settingKey: "storeMode"
        label: "Association Key Storage"
        description: "Where KeePassXC Browser pairing keys are stored (automatically falls back to local file if KeePassXC provides org.freedesktop.secrets)"
        defaultValue: "auto"
        options: [
            { label: "Auto (System Keyring with KeePassXC Secret Service detection)", value: "auto" },
            { label: "Local File Only (~/.local/share/dms/duxKeePassXC)", value: "file" },
            { label: "System Keyring (secret-tool)", value: "keyring" }
        ]
    }

    StringSetting {
        settingKey: "customSocketPath"
        label: "Custom KeePassXC Socket Path"
        description: "Leave empty to auto-detect $XDG_RUNTIME_DIR/org.keepassxc.KeePassXC.BrowserServer"
        placeholder: "Auto-detect ($XDG_RUNTIME_DIR/org.keepassxc.KeePassXC.BrowserServer)"
        defaultValue: ""
    }

    ToggleSetting {
        settingKey: "persistMetadataCache"
        label: "Persist Entry Metadata Cache"
        description: "Cache non-sensitive entry metadata (titles, usernames, URLs, groups) on disk to improve Limited Access Mode search; off by default so metadata is not persisted while KeePassXC is locked"
        defaultValue: false
    }

    StringSetting {
        settingKey: "allowedUrlSchemes"
        label: "Allowed URL Schemes (Open URL)"
        description: "Comma-separated URL schemes allowed by the Open URL action (default: http, https)"
        placeholder: "http, https"
        defaultValue: "http, https"
    }

    ToggleSetting {
        settingKey: "guardEmptyUrlCrash"
        label: "Guard Against KeePassXC 2.8.0 Empty-URL Crash"
        description: "Block get-logins on entries with no URL when connected to KeePassXC 2.7.x–2.8.0 to avoid KeePassXC segfault #13865 (disable if your KeePassXC build includes the fix or you use Additional URLs)"
        defaultValue: true
    }
}

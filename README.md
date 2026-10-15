# Productivity Tools

Small tools that save everyday clicks. Currently: one iPhone shortcut.

## Create Calendar Event (iPhone shortcut)

Copy a message — in Hebrew, Russian or English — run the shortcut, and it becomes a calendar event.

> "Dentist tomorrow at 17:00 at Herzl 10" → **Dentist** · tomorrow 17:00–18:00

### Install

**[⬇ Download the latest version](https://github.com/DinaKleiman/productivity_tools/releases/latest)**

1. Open the link above on your iPhone and download the `iphone_create_calendar_event.public.vX.Y.Z.shortcut` file.
2. Open it from the Files app and tap **Add Shortcut**.
3. Choose the calendar for new events when asked.
4. Open the shortcut and replace `your_name_here` in the name list with your own names.

See all versions and release notes on the [Releases page](https://github.com/DinaKleiman/productivity_tools/releases).

### Requirements

- **iOS 26 or later** with **Apple Intelligence** turned on, and the **ChatGPT extension** enabled.
- iPhone 15 Pro, iPhone 15 Pro Max, or iPhone 16 models or later.
- Apple Intelligence and the ChatGPT extension are not available in all languages or regions.

### How it works

1. Reads the clipboard.
2. Sends the text to ChatGPT (through Apple Intelligence) to extract the title, start, end and location.
3. Asks who the event is for and adds that name to the title.
4. Adds the event to your chosen calendar with an alert 1 day before.

### Privacy

The text on your clipboard is sent to ChatGPT every time the shortcut runs. Don't run it with sensitive text on the clipboard.

### Known limitations

- Location is extracted but not yet added to the event.
- No error message if the text has no date.

## Repository layout

```
IphoneShortcuts/
└── iphone_create_calendar_event.plist   # shortcut source (readable XML)
```

The signed `.shortcut` file is not stored in the repo. It is built from the `.plist` and attached to each [release](https://github.com/DinaKleiman/productivity_tools/releases).

### Building from source (macOS)

Requires a Mac signed in to iCloud.

```bash
plutil -convert binary1 -o /tmp/unsigned.shortcut IphoneShortcuts/iphone_create_calendar_event.plist
shortcuts sign --mode anyone --input /tmp/unsigned.shortcut --output iphone_create_calendar_event.public.vX.Y.Z.shortcut
```

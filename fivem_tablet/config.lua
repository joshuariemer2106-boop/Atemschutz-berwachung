Config = {}

-- Public HTTPS URL of your deployed web app (Render, etc.)
Config.TabletUrl = "https://atemschutz-berwachung.onrender.com/presse"

-- Command to toggle the tablet
Config.Command = "tablet"

-- Separate command used only for key mapping (new name forces fresh default bind)
Config.KeybindCommand = "tablet_toggle"

-- Keyboard mapping (default: F4)
Config.KeybindDescription = "Tablet oeffnen/schliessen"
Config.Keybind = "F4"

-- Disable controls while tablet is open
Config.DisableControls = true
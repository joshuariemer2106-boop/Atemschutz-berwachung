Config = {}

-- Public HTTPS URL for the pure Atemschutz page.
-- Set this to your standalone deployment URL if needed.
Config.TabletUrl = "https://atemschutz-berwachung.onrender.com/atemschutz"

-- Command to toggle the tablet
Config.Command = "tabletasw"

-- Separate command used only for key mapping (new name forces fresh default bind)
Config.KeybindCommand = "tabletasw_toggle"

-- Keyboard mapping (default: F6)
Config.KeybindDescription = "Atemschutz Tablet oeffnen/schliessen"
Config.Keybind = "F6"

-- Disable controls while tablet is open
Config.DisableControls = true

local tabletOpen = false
local keybindCommand = Config.KeybindCommand or (Config.Command .. "_toggle")

local function setTabletOpen(state)
    tabletOpen = state
    SetNuiFocus(state, state)
    SendNUIMessage({
        action = "setVisible",
        visible = state,
        url = Config.TabletUrl
    })
end

local function toggleTablet()
    setTabletOpen(not tabletOpen)
end

RegisterCommand(Config.Command, function()
    toggleTablet()
end, false)

RegisterCommand(keybindCommand, function()
    toggleTablet()
end, false)

RegisterKeyMapping(keybindCommand, Config.KeybindDescription, "keyboard", Config.Keybind)

RegisterNUICallback("close", function(_, cb)
    setTabletOpen(false)
    cb({ ok = true })
end)

AddEventHandler("onClientResourceStart", function(resourceName)
    if resourceName ~= GetCurrentResourceName() then
        return
    end
    setTabletOpen(false)
end)

AddEventHandler("playerSpawned", function()
    setTabletOpen(false)
end)

CreateThread(function()
    while true do
        if tabletOpen and Config.DisableControls then
            DisableControlAction(0, 1, true)   -- LookLeftRight
            DisableControlAction(0, 2, true)   -- LookUpDown
            DisableControlAction(0, 24, true)  -- Attack
            DisableControlAction(0, 25, true)  -- Aim
            DisableControlAction(0, 37, true)  -- Weapon wheel
            DisableControlAction(0, 44, true)  -- Cover
            DisableControlAction(0, 200, true) -- Pause
            DisableControlAction(0, 322, true) -- ESC
            Wait(0)
        else
            Wait(300)
        end
    end
end)

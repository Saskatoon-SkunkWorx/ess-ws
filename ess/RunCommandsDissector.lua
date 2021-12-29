local lib = {}

local f_run_commands = ProtoField.string("ess.run.boot.commands", "[Boot Commands]")
local f_run_command = ProtoField.string("ess.run.boot.command", "Command")

local f_watchdog = ProtoField.string("ess.run.watchdog", "Watchdog")
local f_watchdog_seq = ProtoField.uint8("ess.run.watchdog.seq", "Sequence ID")
local f_watchdog_cmd = ProtoField.bytes("ess.run.watchdoc.cmd", "Command", base.COLON)

local f_unknown = ProtoField.string("ess.unknown", "UNKNOWN")

lib.fields = {
    f_run_commands,
    f_run_command,
    f_watchdog,
    f_watchdog_seq,
    f_watchdog_cmd,
    f_unknown
}

function lib:call(buffer, pinfo, tree)
    local offset = 0

    -- Need to determine if we are AB:00 or AB:08 form
    local b01 = buffer(offset + 1, 1):bytes():get_index(0)
    if b01 == 0x00 then
        local function command_value(tvb)
            local command = tvb:bytes():tohex(false,":")
            return command
        end

        local command_index = 1
        local buffer_length = buffer:len()
        local command_max_len = 4

        local t_commands = tree:add(f_run_commands, buffer(offset), "")

        while offset < buffer_length do
            local label = ("[%d]: %s"):format(command_index, command_value(buffer(offset + 2, 2)))
            t_commands:add(f_run_command, buffer(offset, 4), "", label)

            offset = offset + command_max_len
            command_index = command_index + 1
        end
    elseif b01 == 0x08 then
        local t_watchdog = tree:add(f_watchdog, buffer(offset), "")

        t_watchdog:add_le(f_watchdog_seq, buffer(offset + 3, 1))
        t_watchdog:add(f_watchdog_cmd, buffer(offset + 4))
    else
        tree:add(f_unknown, buffer(offset))
    end

    return buffer:len()
end

return lib
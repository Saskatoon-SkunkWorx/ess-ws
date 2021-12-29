local motion_controller_header_dissector = require 'ess.MotionControllerHeaderDissector'
local run_commands_dissector = require 'ess.RunCommandsDissector'
local run_frames_dissector = require 'ess.RunFramesDissector'

local lib = {}

local motion_controller_payload_ids = {
    ['1F:1F'] = "Run",
    ['A5:A5'] = "Profile",
    ['6B:6B'] = "Start Run",
    ['7C:7C'] = "End Session"
}

local payload_run_ids = {
    ['AB'] = 'AB (171)',
    ['8D'] = '8D (141)',
    ['A3'] = 'A3 (163)',
    ['89'] = '89 (137)',
    ['88'] = '88 (136)',
    ['BD'] = 'BD (189)',
    ['82'] = '82 (130)',
    ['AC'] = 'AC (172)',
    ['00'] = '00 (0)',
    ['EA'] = 'EA (234)',
    ['B3'] = 'B3 (179)',
    ['04'] = '04 (4)',
}

local f_payload_length = ProtoField.uint32("ess.motion.controller.payload.length", "Length")
local f_payload_type = ProtoField.string("ess.motion.controller.payload.type", "Payload Type", base.ASCII)
local f_payload_run_type = ProtoField.string("ess.motion.controller.payload.run.type", "Run Type", base.ASCII)

local f_payload_data = ProtoField.bytes("ess.motion.controller.payload.data", "Payload Data", base.COLON)
local f_profile_data = ProtoField.bytes("ess.motion.controller.profile.data", "Profile Data", base.COLON)

local fields = {
    f_payload_length,
    f_payload_type,
    f_payload_run_type,
    f_payload_data,
    f_profile_data
}

for _, field in ipairs(motion_controller_header_dissector.fields) do
    table.insert(fields, field)
end

for _, field in ipairs(run_frames_dissector.fields) do
    table.insert(fields, field)
end

for _, field in ipairs(run_commands_dissector.fields) do
    table.insert(fields, field)
end

lib.fields = fields

function lib:call(buffer, pinfo, tree)
    local function motion_controller_payload_type(tvb)
        local key = tvb:bytes():tohex(false, ":")
        return motion_controller_payload_ids[key] or "UNKNOWN"
    end

    local function payload_run_type(tvb)
        local key = tvb:bytes():tohex(false, ":")
        return payload_run_ids[key] or "UNKNOWN"
    end

    local offset

    -- Header
    offset = motion_controller_header_dissector:call(buffer, pinfo, tree)

    -- Payload
    local payload_type_buffer = buffer(offset + 2, 2)

    local payload_type = motion_controller_payload_type(payload_type_buffer)
    local t_payload = tree:add(f_payload_type, buffer(offset),
                                    payload_type)

    t_payload:add_le(f_payload_length, buffer(offset, 2))
    offset = offset + 4

    if payload_type == 'Run' then
        local run_type_buffer = buffer(offset, 1)

        local run_type = payload_run_type(run_type_buffer)
        t_payload:add(f_payload_run_type, run_type_buffer, run_type)

        if run_type == 'AB (171)' then
            run_commands_dissector:call(buffer(offset):tvb(), pinfo, t_payload)
        elseif run_type == '8D (141)' then
            run_frames_dissector:call(buffer(offset + 1):tvb(), pinfo, t_payload)
        else
            t_payload:add(f_payload_data, buffer(offset + 1))
        end
    elseif payload_type == 'Profile' then
        t_payload:add(f_profile_data, buffer(offset + 1))
    end
end

return lib

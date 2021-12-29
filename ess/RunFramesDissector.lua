local lib = {}

-- declare unit strings
local signal_ids = {
    ['00:00'] = "LOW",
    ['00:01'] = "LOW>",
    ['20:00'] = "L_W",
    ['3F:3E'] = "HIGH<",
    ['3F:3F'] = "HIGH"
}

local f_run_frames = ProtoField.string("ess.run.frames", "[Frames]")

local f_run_frame_B1 = ProtoField.uint8("ess.run.frame.B1", "B1", base.DEC_HEX)
local f_run_frame_B2 = ProtoField.uint8("ess.run.frame.B2", "B2", base.DEC_HEX)
local f_run_frame_B3 = ProtoField.uint8("ess.run.frame.B3", "B3", base.DEC_HEX)
local f_run_frame_B4 = ProtoField.uint8("ess.run.frame.B4", "B4", base.DEC_HEX)
local f_run_frame_B5 = ProtoField.uint8("ess.run.frame.B5", "B5", base.DEC_HEX)
local f_run_frame_B6_17 = ProtoField.bytes("ess.run.frame.B6_17", "B6_17", base.COLON)
local f_run_frame_B18 = ProtoField.uint8("ess.run.frame.B18", "B18", base.DEC_HEX)
local f_run_frame_B19_24 = ProtoField.bytes("ess.run.frame.B19_24", "B19_24", base.COLON)
local f_run_frame_B25_26 = ProtoField.string("ess.run.frame.B25_26", "B25_26", base.ASCII)
local f_run_frame_B27 = ProtoField.uint8("ess.run.frame.B27", "B27", base.DEC_HEX)
local f_run_frame_B28_29 = ProtoField.string("ess.run.frame.B28_29", "B28_29", base.ASCII)
local f_run_frame_B30 = ProtoField.uint8("ess.run.frame.B30", "B30", base.DEC_HEX)
local f_run_frame_B31_32 = ProtoField.string("ess.run.frame.B31_32", "B31_32", base.ASCII)
local f_run_frame_B33 = ProtoField.uint8("ess.run.frame.B33", "B33", base.DEC_HEX)
local f_run_frame_B34_35 = ProtoField.string("ess.run.frame.B34_35", "B34_35", base.ASCII)

lib.frame_fields = {}

lib.fields = {
    f_run_frames,
    f_run_frame_B1,
    f_run_frame_B2,
    f_run_frame_B3,
    f_run_frame_B4,
    f_run_frame_B5,
    f_run_frame_B6_17,
    f_run_frame_B18,
    f_run_frame_B19_24,
    f_run_frame_B25_26,
    f_run_frame_B27,
    f_run_frame_B28_29,
    f_run_frame_B30,
    f_run_frame_B31_32,
    f_run_frame_B33,
    f_run_frame_B34_35
}

for i = 1,40 do
    -- Add Run Frame
    local f_run_frame = ProtoField.bytes(("ess.run.frame.%02d"):format(i), ("Frame[%d]"):format(i), base.COLON)
    table.insert(lib.frame_fields, f_run_frame)
    table.insert(lib.fields, f_run_frame)
end

function lib:call(buffer, pinfo, tree)
    local function dissect_run_frame(t_parent, offset)
        local function signal_value(tvb)
            local key = tvb:bytes():tohex(false, ":")
            return signal_ids[key] or "UNKNOWN"
        end

        t_parent:add_le(f_run_frame_B1, buffer(offset,1))
        t_parent:add_le(f_run_frame_B2, buffer(offset + 1, 1))
        t_parent:add_le(f_run_frame_B3, buffer(offset + 2, 1))
        t_parent:add_le(f_run_frame_B4, buffer(offset + 3, 1))
        t_parent:add_le(f_run_frame_B5, buffer(offset + 4, 1))
        t_parent:add(f_run_frame_B6_17, buffer(offset + 5, 12))
        t_parent:add_le(f_run_frame_B18, buffer(offset + 17, 1))
        t_parent:add(f_run_frame_B19_24, buffer(offset + 18, 6))

        local b25_26 = buffer(offset + 24, 2)
        t_parent:add(f_run_frame_B25_26, b25_26, signal_value(b25_26))

        t_parent:add_le(f_run_frame_B27, buffer(offset + 26, 1))

        local b28_29 = buffer(offset + 27, 2)
        t_parent:add(f_run_frame_B28_29, b28_29, signal_value(b28_29))

        t_parent:add_le(f_run_frame_B30, buffer(offset + 29, 1))

        local b31_32 = buffer(offset + 30, 2)
        t_parent:add(f_run_frame_B31_32, b31_32, signal_value(b31_32))

        t_parent:add_le(f_run_frame_B33, buffer(offset + 32, 1))

        local b34_35 = buffer(offset + 33, 2)
        t_parent:add(f_run_frame_B34_35, b34_35, signal_value(b34_35))
    end

    local frame_index = 1
    local buffer_length = buffer:len()
    local offset = 0
    local frame_max_len = 35

    local t_frames = tree:add(f_run_frames, buffer(offset), '')

    while offset < buffer_length do
        local f_run_frame = lib.frame_fields[frame_index]
        -- Add Frame Data as Segments
        if offset + frame_max_len > buffer_length then
            -- Skip the partial frame at the end
            -- t_frames:add(f_run_frame, buffer(offset))
        else
            local t_run_frame = t_frames:add(f_run_frame, buffer(offset, frame_max_len))
            dissect_run_frame(t_run_frame, offset)
        end

        offset = offset + frame_max_len
        frame_index = frame_index + 1
    end

    return buffer:len()
end


return lib
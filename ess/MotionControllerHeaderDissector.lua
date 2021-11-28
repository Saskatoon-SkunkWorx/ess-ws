local lib = {}

local message_ids = {
    ['EE:EE:EE:EE'] = "Normal"
}

local f_message_type = ProtoField.string("ess.motion.controller.type", "Message Type", base.ASCII)
local f_length = ProtoField.uint16("ess.length", "Length")
local f_complement = ProtoField.int16("ess.complement", "Complement")
local f_header = ProtoField.string("ess.motion.controller.header", "Header")
local f_message_seq = ProtoField.uint32("ess.motion.controller.seq", "Message Sequence")
local f_message_sub_seq = ProtoField.uint32("ess.motion.controller.sub.seq", "Message Sub Sequence")
local f_filler = ProtoField.uint16("ess.filler", "Filler")

lib.fields = {
    f_message_type,
    f_length,
    f_complement,
    f_header,
    f_message_seq,
    f_message_sub_seq,
    f_filler
}

function lib:call(buffer, pinfo, tree)
    local function message_type(tvb)
        local key = tvb:bytes():tohex(false, ":")
        return message_ids[key] or "UNKNOWN"
    end

    local header_length = 16

    local sequence = buffer(12, 4)
    local sub_sequence = buffer(6, 2)
    local t_header = tree:add(f_header, buffer(0, header_length), ("%d.%d"):format(sequence:le_uint(), sub_sequence:le_uint()))

    t_header:add_le(f_message_seq, sequence)
    t_header:add_le(f_message_sub_seq, sub_sequence)

    t_header:add_le(f_length, buffer(0,2))
    t_header:add_le(f_complement, buffer(2,2))

    local message_type_buffer = buffer(8, 4)
    t_header:add(f_message_type, message_type_buffer, message_type(message_type_buffer))

    t_header:add_le(f_filler, buffer(4, 2))

    return header_length
end


return lib
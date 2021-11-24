local lib = {}

local send_ids = {
    ['EE:EE:EE:EE'] = "Normal"
}

local f_send_type = ProtoField.string("ess.send.type", "Send Type", base.ASCII)
local f_length = ProtoField.uint16("ess.length", "Length")
local f_complement = ProtoField.int16("ess.complement", "Complement")
local f_header = ProtoField.string("ess.send.header", "Send Header")
local f_send_seq = ProtoField.uint32("ess.send.seq", "Sequence")
local f_send_sub_seq = ProtoField.uint32("ess.send.sub.seq", "Sub Sequence")
local f_filler = ProtoField.uint16("ess.filler", "Filler")

lib.fields = {
    f_send_type,
    f_length,
    f_complement,
    f_header,
    f_send_seq,
    f_send_sub_seq,
    f_filler
}

function lib:call(buffer, pinfo, tree)
    local function send_type(tvb)
        local key = tvb:bytes():tohex(false, ":")
        return send_ids[key] or "UNKNOWN"
    end

    local header_length = 16

    local sequence = buffer(12, 4)
    local sub_sequence = buffer(6, 2)
    local t_header = tree:add(f_header, buffer(0, header_length), ("%d.%d"):format(sequence:le_uint(), sub_sequence:le_uint()))

    t_header:add_le(f_send_seq, sequence)
    t_header:add_le(f_send_sub_seq, sub_sequence)

    t_header:add_le(f_length, buffer(0,2))
    t_header:add_le(f_complement, buffer(2,2))

    local send_type_buffer = buffer(8, 4)
    t_header:add(f_send_type, send_type_buffer, send_type(send_type_buffer))

    t_header:add_le(f_filler, buffer(4, 2))

    return header_length
end


return lib
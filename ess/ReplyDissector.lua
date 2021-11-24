local lib = {}

local reply_ids = {
    ['00:00:00:00'] = "Begin",
    ['11:11:11:11'] = "Type 1",
    ['22:22:22:22'] = "Type 2",
    ['33:33:33:33'] = "End"
}

local f_length = ProtoField.uint16("ess.length", "Length")
local f_complement = ProtoField.int16("ess.complement", "Complement")
local f_reply_type = ProtoField.string("ess.reply.type", "Reply Type", base.ASCII)
local f_active_seq_1 = ProtoField.uint32("ess.reply.active.seq.1", "Active Sequence(1)")
local f_active_seq_2 = ProtoField.uint32("ess.reply.active.seq.2", "Active Sequence(2)")
local f_server_ip = ProtoField.ipv4("ess.server.ip", "Server IP")
local f_device_ip = ProtoField.ipv4("ess.device.ip", "Device IP")
local f_bytes_received = ProtoField.uint32("ess.reply.bytes.received", "Bytes Received")

local f_cfg_seq = ProtoField.uint32("ess.reply.cfg.seq", "CFG Sequence")
local f_cfg_bytes_received = ProtoField.uint32("ess.reply.cfg.bytes.received", "CFG Bytes Received")

local f_reply_seq = ProtoField.uint32("ess.reply.seq", "Reply Sequence")
local f_reply_seq_overflow = ProtoField.uint32("ess.reply.seq.overflow", "Reply Sequence Overflow")

lib.fields = {
    f_length,
    f_complement,
    f_reply_type,
    f_active_seq_1,
    f_active_seq_2,
    f_server_ip,
    f_device_ip,
    f_bytes_received,
    f_cfg_seq,
    f_cfg_bytes_received,
    f_reply_seq,
    f_reply_seq_overflow
}

function lib:call(buffer, pinfo, tree)
    local function reply_type(tvb)
        local key = tvb:bytes():tohex(false, ":")
        return reply_ids[key] or "UNKNOWN"
    end

    local buffer_length = buffer:len()
    local offset = 0

    tree:add_le(f_length, buffer(offset,2))
    tree:add_le(f_complement, buffer(offset + 2,2))
    offset = offset + 4
    
    local reply_type_buffer = buffer(offset, 4)
    tree:add(f_reply_type, reply_type_buffer, reply_type(reply_type_buffer))
    offset = offset + 4

    tree:add_le(f_active_seq_1, buffer(offset,4))
    offset = offset + 4

    tree:add(f_device_ip, buffer(offset, 4))
    tree:add(f_server_ip, buffer(offset + 4, 4))
    offset = offset + 8

    tree:add_le(f_active_seq_2, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_bytes_received, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_reply_seq, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_reply_seq_overflow, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_cfg_seq, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_cfg_bytes_received, buffer(offset,4))
    offset = offset + 4


    return buffer:len()
end

return lib
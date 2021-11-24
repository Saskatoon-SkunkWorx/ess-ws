local send_header_dissector = require'ess.SendHeaderDissector'
local run_frames_dissector = require 'ess.RunFramesDissector'
local reply_dissector = require 'ess.ReplyDissector'

local ess_udp_proto = Proto("ess-udp", "Ethernet Smooth Stepper")

-- declare unit strings
local send_payload_ids = {
    ['1F:1F'] = "Run",
    ['A5:A5'] = "Profile",
    ['6B:6B'] = "End Profile",
    ['7C:7C'] = "End Session"
}

local send_payload_run_ids = {
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

-- declare fields
local f_magic_string = ProtoField.string("ess.wakeup", "Magic Wake-up")
local f_counter = ProtoField.uint32("ess.counter", "Counter")
local f_data = ProtoField.bytes("ess.data", "Data", base.COLON)
local f_device_name = ProtoField.string("ess.name", "Device Name")
local f_message_type_long = ProtoField.bytes("ess.message.type.full", "Message (Long)", base.COLON)
local f_message_type_short = ProtoField.uint16("ess.message.type", "Message", base.DEC_HEX)
local f_server_ether = ProtoField.ether("ess.server.ether", "Server Ethernet")
local f_server_ip = ProtoField.ipv4("ess.server.ip", "Server IP")
local f_device_ether = ProtoField.ether("ess.device.ether", "Device Ethernet")
local f_device_ip = ProtoField.ipv4("ess.device.ip", "Device IP")
local f_packet_count = ProtoField.uint32("ess.packet.count", "Packet Counter")

local f_count = ProtoField.uint32("ess.count", "Count")

local f_length = ProtoField.uint16("ess.length", "Length")
local f_complement = ProtoField.int16("ess.complement", "Complement")
local f_payload = ProtoField.string("ess.payload", "Payload")
local f_payload_length = ProtoField.uint32("ess.payload.length", "Length")
local f_send_payload_type = ProtoField.string("ess.send.payload.type", "Send Payload Type", base.ASCII)
local f_send_payload_run_type = ProtoField.string("ess.send.payload.run.type", "Run Type", base.ASCII)
local f_send_payload_data = ProtoField.bytes("ess.send.payload.data", "Payload Data", base.COLON)
local f_send_profile_data = ProtoField.bytes("ess.send.profile.data", "Profile Data", base.COLON)

-- declare generic fields for exploration purposes
local f_chunk = ProtoField.bytes("ess.chunk", "Chunk", base.COLON)
local f_char = ProtoField.char("ess.char", "Char")
local f_int16 = ProtoField.int16("ess.int16", "Int16")
local f_uint16 = ProtoField.uint16("ess.uint16", "UInt16")
local f_int32 = ProtoField.int32("ess.int32", "Int32")
local f_uint32 = ProtoField.uint32("ess.uint32", "UInt32")
local f_float = ProtoField.float("ess.float", "Float")

local fields = {
    f_magic_string,
    f_counter,
    f_data,
    f_device_name,
    f_message_type_short,
    f_message_type_long,
    f_server_ether,
    f_server_ip,
    f_device_ether,
    f_device_ip,
    f_packet_count,
    f_chunk,
    f_char,
    f_int16,
    f_uint16,
    f_int32,
    f_uint32,
    f_float,
    f_length,
    f_complement,
    f_count,
    f_payload,
    f_payload_length,
    f_send_payload_type,
    f_send_payload_run_type,
    f_send_payload_data,
    f_send_profile_data
}

for _, field in ipairs(run_frames_dissector.fields) do
    table.insert(fields, field)
end

for _, field in ipairs(reply_dissector.fields) do
    table.insert(fields, field)
end

for _, field in ipairs(send_header_dissector.fields) do
    table.insert(fields, field)
end

ess_udp_proto.fields = fields

-- define the dissection function
function ess_udp_proto.dissector(buffer, pinfo, tree)
    local function dissect_chunk(offset, t_parent, index)
        local t_group = t_parent:add(buffer(offset,4), ("Chunk %d"):format(index), buffer(offset,4):bytes():tohex(false,":"))
        t_group:add_le(f_int16, buffer(offset, 2))
        t_group:add_le(f_int16, buffer(offset + 1, 2))
        t_group:add_le(f_int16, buffer(offset + 2, 2))

        t_group:add_le(f_uint16, buffer(offset, 2))
        t_group:add_le(f_uint16, buffer(offset + 1, 2))
        t_group:add_le(f_uint16, buffer(offset + 2, 2))

        t_group:add_le(f_int32, buffer(offset, 4))
        t_group:add_le(f_uint32, buffer(offset, 4))

        t_group:add_le(f_float, buffer(offset, 4))

        return offset + 4
    end

    local function dissect_dst_port_9()
        -- create the ESS/UDP Protocol Tree item
        local t_ess_udp = tree:add(ess_udp_proto, buffer())
        local offset = 0

        -- Field - Magic String
        local magic_string = buffer:range():stringz()
        t_ess_udp:add(f_magic_string, buffer(0,#magic_string + 1), magic_string)
        offset = offset + #magic_string + 1

        -- Field - Counter
        t_ess_udp:add_le(f_counter, buffer(offset,4))
        offset = offset + 4

        -- Add 4 Byte Undetermined Fields
        for idx = 1,4 do
            offset = dissect_chunk(offset, t_ess_udp, idx)
        end
    end

    local function dissect_src_port_9()
        -- create the ESS/UDP Protocol Tree Item
        local t_ess_udp = tree:add(ess_udp_proto, buffer())
        local offset = 0

        -- Field - Device Name
        local device_name = buffer(offset, 64):stringz()
        local device_name_len = buffer(offset, 64):strsize()
        t_ess_udp:add(f_device_name, buffer(0,device_name_len), device_name)
        offset = offset + 64    -- we skip the info after the device name as we don't know what it does

        -- Message
        local t_message_type = t_ess_udp:add(f_message_type_short, buffer(offset,1))
        t_message_type:add(f_message_type_long, buffer(offset,6))
        offset = offset + 8

        -- Server Ethernet
        t_ess_udp:add(f_server_ether, buffer(offset,6))
        offset = offset + 8

        -- Server IP
        t_ess_udp:add(f_server_ip, buffer(offset,4))
        offset = offset + 4

        -- Device Ethernet
        t_ess_udp:add(f_device_ether, buffer(offset,6))
        offset = offset + 8

        -- Device IP
        t_ess_udp:add(f_device_ip, buffer(offset,4))
        offset = offset + 4

        -- Add 4 Byte Undetermined Fields
        for idx = 1,8 do
            offset = dissect_chunk(offset, t_ess_udp, idx)
        end

        -- Add Packet Counter
        t_ess_udp:add_le(f_packet_count, buffer(offset, 4))
    end

    local function dissect_dst_port_4096()
        local function send_payload_type(tvb)
            local key = tvb:bytes():tohex(false, ":")
            return send_payload_ids[key] or "UNKNOWN"
        end

        local function send_run_type(tvb)
            local key = tvb:bytes():tohex(false, ":")
            return send_payload_run_ids[key] or "UNKNOWN"
        end

        -- create the ESS/UDP Protocol Tree Item
        local t_ess_udp = tree:add(ess_udp_proto, buffer())
        local offset

        -- Header
        offset = send_header_dissector:call(buffer, pinfo, t_ess_udp)

        -- Payload
        local send_payload_type_buffer = buffer(offset + 2, 2)

        local payload_type = send_payload_type(send_payload_type_buffer)
        local t_payload = t_ess_udp:add(f_send_payload_type, buffer(offset), payload_type)

        t_payload:add_le(f_payload_length, buffer(offset, 2))
        offset = offset + 4

        if payload_type == 'Run' then
            local run_type_buffer = buffer(offset, 1)

            local run_type = send_run_type(run_type_buffer)
            t_payload:add(f_send_payload_run_type, run_type_buffer, run_type)
            offset = offset + 1

            if run_type == '8D (141)' then
                run_frames_dissector:call(buffer(offset):tvb(), pinfo, t_payload)
            else
                t_payload:add(f_send_payload_data, buffer(offset))
            end
        elseif payload_type == 'Profile' then
            t_payload:add(f_send_profile_data, buffer(offset))
        end
    end

    local function dissect_src_port_4096()
        -- create the ESS/UDP Protocol Tree Item
        local t_ess_udp = tree:add(ess_udp_proto, buffer())

        reply_dissector:call(buffer, pinfo, t_ess_udp)
    end

    -- Set the protocol column
    pinfo.cols.protocol = "ESS/UDP"

    if pinfo.dst_port == 9 then
        dissect_dst_port_9()
    elseif pinfo.src_port == 9 then
        dissect_src_port_9()
    elseif pinfo.dst_port == 4096 then
        dissect_dst_port_4096()
    elseif pinfo.src_port == 4096 then
        dissect_src_port_4096()
    end
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(9, ess_udp_proto)
udp_table:add(4096, ess_udp_proto)

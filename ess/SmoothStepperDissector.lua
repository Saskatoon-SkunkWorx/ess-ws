local lib = {}

local message_ids = {
    ['00:00:00:00'] = "Start",
    ['11:11:11:11'] = "RunStatus 1",
    ['22:22:22:22'] = "RunStatus 2",
    ['33:33:33:33'] = "End"
}

local f_length = ProtoField.uint16("ess.length", "Length")
local f_complement = ProtoField.int16("ess.complement", "Complement")
local f_smooth_stepper_message_type = ProtoField.string("ess.smooth.stepper.message.type", "Message Type", base.ASCII)
local f_active_seq_1 = ProtoField.uint32("ess.reply.active.seq.1", "Active Sequence(1)")
local f_active_seq_2 = ProtoField.uint32("ess.reply.active.seq.2", "Active Sequence(2)")
local f_motion_controller_ip = ProtoField.ipv4("ess.motion_controller.ip", "MotionController IP")
local f_smooth_stepper_ip = ProtoField.ipv4("ess.smooth.stepper.ip", "SmoothStepper IP")
local f_bytes_received = ProtoField.uint32("ess.reply.bytes.received", "Bytes Received")

local f_profile_seq = ProtoField.uint32("ess.smooth.stepper.profile.seq", "Profile Sequence")
local f_profile_bytes_received = ProtoField.uint32("ess.smooth.stepper.profile.bytes.received", "Profile Bytes Received")

local f_message_seq = ProtoField.uint32("ess.smooth.stepper.message.seq", "Message Sequence")
local f_message_seq_overflow = ProtoField.uint32("ess.smooth.stepper.message.seq.overflow", "Message Sequence Overflow")

local f_profile_checksum = ProtoField.bytes("ess.smooth.stepper.profile.checksum", "Profile Checksum", base.COLON)
local f_profile_checksum_counter = ProtoField.uint16("ess.smooth.stepper.profile.checksum.counter", "Profile Checksum Counter")

local f_run_seq = ProtoField.uint32("ess.smooth.stepper.run.seq", "Run Sequence")
local f_run_bytes_received = ProtoField.uint32("ess.smooth.stepper.run.bytes.received", "Run Bytes Received")

lib.fields = {
    f_length,
    f_complement,
    f_smooth_stepper_message_type,
    f_active_seq_1,
    f_active_seq_2,
    f_motion_controller_ip,
    f_smooth_stepper_ip,
    f_bytes_received,
    f_profile_seq,
    f_profile_bytes_received,
    f_message_seq,
    f_message_seq_overflow,
    f_profile_checksum,
    f_profile_checksum_counter,
    f_run_seq,
    f_run_bytes_received
}

function lib:call(buffer, pinfo, tree)
    local function message_type(tvb)
        local key = tvb:bytes():tohex(false, ":")
        return message_ids[key] or "UNKNOWN"
    end

    local offset = 0

    tree:add_le(f_length, buffer(offset,2))
    tree:add_le(f_complement, buffer(offset + 2,2))
    offset = offset + 4

    local message_type_buffer = buffer(offset, 4)
    tree:add(f_smooth_stepper_message_type, message_type_buffer, message_type(message_type_buffer))
    offset = offset + 4

    tree:add_le(f_active_seq_1, buffer(offset,4))
    offset = offset + 4

    tree:add(f_smooth_stepper_ip, buffer(offset, 4))
    tree:add(f_motion_controller_ip, buffer(offset + 4, 4))
    offset = offset + 8

    tree:add_le(f_active_seq_2, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_bytes_received, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_message_seq, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_message_seq_overflow, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_profile_seq, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_profile_bytes_received, buffer(offset,4))
    offset = offset + 4

    tree:add(f_profile_checksum, buffer(offset,2))
    tree:add_le(f_profile_checksum_counter, buffer(offset + 2, 2))
    offset = offset + 4

    tree:add_le(f_run_seq, buffer(offset,4))
    offset = offset + 4

    tree:add_le(f_run_bytes_received, buffer(offset, 4))
    offset = offset + 4

    return buffer:len()
end

return lib
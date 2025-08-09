-- SPDX-License-Identifier: MIT
-- Copyright 2025 Pieszka
-- ATM over TCP (ATMTCP) dissector with LLC encapsulation support
local p_atmtcp = Proto("atmotcp", "ATM over TCP Enhanced")

-- ATMTCP Header Fields
local f_atmtcp_vpi = ProtoField.uint16("atmtcp.vpi", "VPI", base.DEC)
local f_atmtcp_vci = ProtoField.uint16("atmtcp.vci", "VCI", base.DEC)
local f_atmtcp_length = ProtoField.uint32("atmtcp.length", "Length", base.DEC)

-- LLC Fields
local f_llc_header = ProtoField.bytes("atmtcp.llc", "LLC Header")
local f_llc_dsap = ProtoField.uint8("atmtcp.llc.dsap", "DSAP", base.HEX)
local f_llc_ssap = ProtoField.uint8("atmtcp.llc.ssap", "SSAP", base.HEX)
local f_llc_control = ProtoField.uint8("atmtcp.llc.control", "Control", base.HEX)
local f_llc_oui = ProtoField.bytes("atmtcp.llc.oui", "OUI")
local f_llc_ethertype = ProtoField.uint16("atmtcp.llc.ethertype", "EtherType", base.HEX)

-- EtherType table
local ethertypes = {
    [0x0800] = "IPv4",
    [0x86DD] = "IPv6"
}

-- PID definitions for Bridged Ethernet
local pids = {
    [0x0001] = "Ethernet with FCS",
    [0x0007] = "Ethernet without FCS"
}

-- NLPID protocol table
local nlpids = {
    [0xCC] = "IPv4",
    [0x8E] = "IPv6",
	[0xCF] = "Point-to-Point Protocol over ATM/AAL5"
}

p_atmtcp.fields = {
    f_atmtcp_vpi, f_atmtcp_vci, f_atmtcp_length,
    f_llc_header, f_llc_dsap, f_llc_ssap, f_llc_control, f_llc_oui, f_llc_ethertype
}

-- Constants
local ATMTCP_HDR_MAGIC = 0xFFFFFFFF
local ATMTCP_HEADER_LEN = 8  -- VPI(2) + VCI(2) + Length(4)
local LLC_HEADER_LEN = 8     -- DSAP(1) + SSAP(1) + Control(1) + OUI(3) + EtherType(2)

function p_atmtcp.dissector(buffer, pinfo, tree)
    local offset = 0
    local buffer_len = buffer:len()
    
    -- Validate minimum length
    if buffer_len < ATMTCP_HEADER_LEN then
        return false
    end
    
    -- Set protocol column
    pinfo.cols.protocol = p_atmtcp.name
    
    -- Create ATMTCP tree
    local atmtcp_tree = tree:add(p_atmtcp, buffer(), "ATM over TCP")
    
    -- Dissect ATMTCP header
    local vpi = buffer(offset, 2):uint()
    atmtcp_tree:add(f_atmtcp_vpi, buffer(offset, 2))
    offset = offset + 2
    
    local vci = buffer(offset, 2):uint()
    atmtcp_tree:add(f_atmtcp_vci, buffer(offset, 2))
    offset = offset + 2
    
    local length = buffer(offset, 4):uint()
    local length_item = atmtcp_tree:add(f_atmtcp_length, buffer(offset, 4))
    offset = offset + 4
    
    -- Check if this is a command or data
    if length == ATMTCP_HDR_MAGIC then
        pinfo.cols.info:append(" (Command)")
        length_item:append_text(" (Command)")
        -- Command dissection would go here
        return true
    else
        pinfo.cols.info:append(string.format(" (VPI:%d, VCI:%d)", vpi, vci))
        length_item:append_text(" (Data)")
    end
    
     -- Check for LLC encapsulation (exactly 8 bytes: AA-AA-03-00-00-00-XX-XX)
    if buffer_len >= offset + 8 then
        local llc_bytes = buffer(offset, 3):bytes()
        local oui_bytes = buffer(offset+3, 3):bytes()
        
		-- Case 1: Routed non-NLPID (AA-AA-03 + OUI 00-00-00)
        if llc_bytes:get_index(0) == 0xAA and 
           llc_bytes:get_index(1) == 0xAA and
           llc_bytes:get_index(2) == 0x03 and
           oui_bytes:get_index(0) == 0x00 and
           oui_bytes:get_index(1) == 0x00 and
           oui_bytes:get_index(2) == 0x00 then
            
            -- Get EtherType and protocol name
            local ethertype = buffer(offset+6, 2):uint()
            local ethertype_name = ethertypes[ethertype] or string.format("Unknown (0x%04x)", ethertype)
            
            -- Add RFC-compliant LLC encapsulation header
            local llc_tree = tree:add(p_atmtcp, buffer(offset, 8), "LLC Encapsulation - Routed non-NLPID (RFC 1483/2684)")
            
            -- Add protocol information
            llc_tree:add(buffer(offset+6, 2), "Protocol: " .. ethertype_name)
            
            -- Add detailed LLC fields (collapsed by default)
            llc_tree:add(f_llc_dsap, buffer(offset, 1)):append_text(" (SNAP)")
            llc_tree:add(f_llc_ssap, buffer(offset+1, 1)):append_text(" (SNAP)")
            llc_tree:add(f_llc_control, buffer(offset+2, 1))
            llc_tree:add(f_llc_oui, buffer(offset+3, 3)):append_text(" (Ethernet)")
            llc_tree:add(f_llc_ethertype, buffer(offset+6, 2)):append_text(" ("..ethertype_name..")")
            
            offset = offset + 8
            
            -- Try to dissect payload
            if offset < buffer_len then
                local dissector = DissectorTable.get("ethertype"):get_dissector(ethertype)
                if dissector then
                    dissector:call(buffer(offset):tvb(), pinfo, tree)
                else
                    tree:add(buffer(offset), "Payload ("..ethertype_name..")")
                end
            end
            return true
        
		-- Case 2: Routed NLPID (FE-FE-03)
        elseif llc_bytes:get_index(0) == 0xFE and
               llc_bytes:get_index(1) == 0xFE and
               llc_bytes:get_index(2) == 0x03 and
               buffer_len >= offset + 4 then
            
            local llc_tree = tree:add(p_atmtcp, buffer(offset,4), "LLC Encapsulation - Routed NLPID (RFC 1483/2684)")
            local nlp_id = buffer(offset+3,1):uint()
            local nlp_name = nlpids[nlp_id] or string.format("Unknown (0x%02x)", nlp_id)
            
            llc_tree:add(buffer(offset+3,1), "Protocol: "..nlp_name)
            offset = offset + 4
            
            -- Dissect payload based on NLPID
            if offset < buffer_len then
                if nlp_id == 0xCC then  -- IPv4
                    Dissector.get("ip"):call(buffer(offset):tvb(), pinfo, tree)
                elseif nlp_id == 0x8E then  -- IPv6
                    Dissector.get("ipv6"):call(buffer(offset):tvb(), pinfo, tree)
                elseif nlp_id == 0xCF then  -- PPP
                    Dissector.get("ppp"):call(buffer(offset):tvb(), pinfo, tree)
                else
                    tree:add(buffer(offset), "Payload ("..nlp_name..")")
                end
            end
            return true
        -- Case 3: Bridged Ethernet (AA-AA-03 + OUI 00-80-C2)
        elseif llc_bytes:get_index(0) == 0xAA and
               llc_bytes:get_index(1) == 0xAA and
               llc_bytes:get_index(2) == 0x03 and
               buffer_len >= offset + 8 and
               buffer(offset+3,3):bytes():tohex() == "0080C2" then
            
            local llc_tree = tree:add(p_atmtcp, buffer(offset,8), "LLC Encapsulation - Bridged (RFC 1483/2684)")
            
            -- Dissect PID field
            local pid = buffer(offset+6,2):uint()
            local pid_name = pids[pid] or string.format("Unknown PID (0x%04x)", pid)
            llc_tree:add(buffer(offset+6,2), "PID: "..pid_name)
            offset = offset + 8
            
            -- Skip PAD if present (2 bytes)
            if buffer_len >= offset + 2 and buffer(offset,2):uint() == 0 then
                llc_tree:add(buffer(offset,2), "PAD: 0x0000")
                offset = offset + 2
            end
            
            -- Dissect Ethernet frame
            if offset < buffer_len then
                local eth_dissector = Dissector.get("eth_withoutfcs")
                if eth_dissector then
                    -- Create new tvb without potential FCS if PID indicates FCS
                    local eth_end = (pid == 0x0001) and -4 or nil
                    eth_dissector:call(buffer(offset, eth_end):tvb(), pinfo, tree)
                else
                    tree:add(buffer(offset), "Ethernet Frame")
                end
            end
            return true
        end
    end
    
    -- Non-LLC payload
    if offset < buffer_len then
        tree:add(buffer(offset), "Data: "..buffer(offset):bytes():tohex())
    end
    
    return true
end

-- Register the dissector
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(2812, p_atmtcp)

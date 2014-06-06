#!/bin/usr/lua

sys = require "luci.sys"

ct = {}
sys.net.conntrack(function(ent)
	if ct[ent.src] == nil then
		ct[ent.src] = { count = 0, pkts = 0, bytes = 0 }
	end
	ct[ent.src].count = ct[ent.src].count + 1
	ct[ent.src].pkts = ct[ent.src].pkts + ent.packets
	ct[ent.src].bytes = ct[ent.src].bytes + ent.bytes
end)

print("ip count pkts bytes")
for k, v in pairs(ct) do
	print(k .. " " .. v.count .. " " .. v.pkts .. " " .. v.bytes)
end

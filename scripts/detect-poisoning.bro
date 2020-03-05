##! Detect the receipt of several old packets (retransmitted by publisher),
##! which will indicate an MITM poisoning attack.

@load base/frameworks/notice

module GOOSE;

## Threshold for attack indictor: number of packets received with old sqNum that signifies an attack.
global detection_threshold = 3;

# Record to hold latest timestamp, stNum, and sqNum.
type StateRec: record {
	ts: double;
	st: count;
	sq: count;
};

# [src_mac] -> {capture_time, latest_st_num, latest_sq_num}
global src_state_map: table[string] of StateRec;

# [src_mac] -> count_old_state_transmitted
global old_retransmission_map: table[string] of count;

# Set to hold source MAC addresses which have been found to be attack sources so far.
global attack_sources: set[string];

export {
        redef enum Notice::Type += { GOOSE_Poisoning }; 
}

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
        {
	local src_mac = info$source;
	local dst_mac = info$destination;
	local timestamp = info$captureTime;
        local st_num = pdu$stNum;
        local sq_num = pdu$sqNum;

	if ( src_mac !in src_state_map )
		{
		src_state_map[src_mac] = [$ts = timestamp, $st = st_num, $sq = sq_num];
		old_retransmission_map[src_mac] = 0;
		}
	else
		{
		if ( timestamp > src_state_map[src_mac]$ts )
			{
			if ( st_num > src_state_map[src_mac]$st )
				{
				src_state_map[src_mac] = [$ts = timestamp, $st = st_num, $sq = sq_num];
				}
			else if ( st_num == src_state_map[src_mac]$st && sq_num > src_state_map[src_mac]$sq)
				{
				src_state_map[src_mac] = [$ts = timestamp, $st = st_num, $sq = sq_num];
				}
			else if ( st_num < src_state_map[src_mac]$st )
				{
				old_retransmission_map[src_mac] += 1;
				if ( old_retransmission_map[src_mac] >= detection_threshold )
					{
					if ( src_mac !in attack_sources )
						{
						add attack_sources[src_mac];
						# Generate attack-detection notice.
						NOTICE([$note=GOOSE_Poisoning,
                                			$msg=fmt("GOOSE poisoning attempt detected: source %s, attack stNum %d, and sqNum %d",
                                        			src_mac, src_state_map[src_mac]$st, src_state_map[src_mac]$sq)
                                			]);
						}
					else
						{
						# Generate attack-continuation notice.
						NOTICE([$note=GOOSE_Poisoning,
                                			$msg=fmt("GOOSE poisoning attempt continued: source %s, attack stNum %d, and sqNum %d",
                                        			src_mac, src_state_map[src_mac]$st, src_state_map[src_mac]$sq)
                                			]);
						}
					# Reset counter.
					old_retransmission_map[src_mac] = 0;
					}
				}
			# Todo, other cases, if important, under 'else'
			}
		}

        }

##! Detect the receipt of several old packets (retransmitted by publisher),
##! which will indicate an MITM poisoning attack.

@load base/frameworks/notice

module GOOSE;

const MAX_ST = 65535; # 2**16 - 1
const MAX_SQ = 65535;
## Threshold for attack indictor:
## number of voilations more than the threshold would signify an attack.
const DETECTION_THRESHOLD = 3;

# Record to hold attributes from last relevant packet.
type StateRec: record {
	src: string;
	dst: string;
	ts: time;
	st: count;
	sq: count;
};

# [dataSet] -> {src_mac, dst_mac, capture_time, latest_st_num, latest_sq_num}
global src_state_map: table[string] of StateRec;

# [dataSet] -> count_old_state_number_transmitted
global invalid_st_replay : table[string] of count;
# [dataSet] -> count_old_sequence_number_transmitted
global invalid_sq_replay: table[string] of count;

# Set to hold dataSets that have been found to be attack sources so far.
global attack_sources: set[string];

export {
        redef enum Notice::Type += { GOOSE_Poisoning }; 
}

function handle_replay_attack(data_set: string, field: string)
	{
	# Generate notices given a GOOSE attack packet.
	local field_name = "StNum";
	if ( field == "sq")
		field_name = "SqNum";
	if ( data_set !in attack_sources )
		{
		add attack_sources[data_set];
		# Generate attack-detection notice.
		NOTICE([$note=GOOSE_Poisoning,
			$msg=fmt("GOOSE replay attempt detected with invalid %s: src_mac %s, data_set %s attack st_num %d, and sq_num %d",
				field_name, src_state_map[data_set]$src, data_set, src_state_map[data_set]$st, src_state_map[data_set]$sq)
			]);
		}
	else
		{
		# Generate attack-continuation notice.
		NOTICE([$note=GOOSE_Poisoning,
			$msg=fmt("GOOSE replay attempt continued with invalid %s: src_mac %s, data_set %s attack st_num %d, and sq_num %d",
				field_name, src_state_map[data_set]$src, data_set, src_state_map[data_set]$st, src_state_map[data_set]$sq)
			]);
		}	
	}

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
        {
	local src_mac = info$source;
	local dst_mac = info$destination;
	local timestamp = network_time(); # info$captureTime;
	local data_set = pdu$datSet;
        local st_num = pdu$stNum;
        local sq_num = pdu$sqNum;

	if ( data_set !in src_state_map )
		{
		src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = timestamp, $st = st_num, $sq = sq_num];
		invalid_st_replay[data_set] = 0;
		invalid_sq_replay[data_set] = 0;
		}
	else
		{
		# Only consider the packets that are captured at a later time after the last seen packet.
		if ( timestamp >= src_state_map[data_set]$ts )
			{
			if ( st_num > src_state_map[data_set]$st || src_state_map[data_set]$st == MAX_ST ) 
				{
				# Transmission of new state.
				src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = timestamp, $st = st_num, $sq = sq_num];
				}
			else if ( st_num == src_state_map[data_set]$st )
				{
				# Re-transmission.
				if ( sq_num > src_state_map[data_set]$sq || src_state_map[data_set]$sq == MAX_SQ)
					{
					src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = timestamp, $st = st_num, $sq = sq_num];
					}
				else
					{
					# Invalid sqNum.
					invalid_sq_replay[data_set] += 1;
					if ( invalid_sq_replay[data_set] >= DETECTION_THRESHOLD )
						{
						handle_replay_attack(data_set, "sq");
						# Reset counter.
						invalid_sq_replay[data_set] = 0;
						src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = timestamp, $st = st_num, $sq = sq_num];
						}
					
					}
				}
			else # st_num < src_state_map[data_set]$st
				{
				invalid_st_replay[data_set] += 1;
				if ( invalid_st_replay[data_set] >= DETECTION_THRESHOLD )
					{
					handle_replay_attack(data_set, "st");
					# Reset counter.
					invalid_st_replay[data_set] = 0;
					src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = timestamp, $st = st_num, $sq = sq_num];
					}
				}
			}
		}

        }

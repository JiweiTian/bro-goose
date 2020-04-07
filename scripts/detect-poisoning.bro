##! Detect the receipt of several old packets (retransmitted by publisher),
##! which will indicate an MITM poisoning attack.

@load base/frameworks/notice

module GOOSE;

const MAX_ST = 65535; # 2**16 - 1
const MAX_SQ = 65535;
## Threshold for attack indictor: number of packets received with old sqNum that signifies an attack.
const DETECTION_THRESHOLD = 3;

# Record to hold latest timestamp, stNum, and sqNum.
type StateRec: record {
	ts: double;
	st: count;
	sq: count;
};

# [src_mac] -> {capture_time, latest_st_num, latest_sq_num}
global src_state_map: table[string] of StateRec;

# [src_mac] -> count_old_state_number_transmitted
global invalid_st_replay : table[string] of count;
# [src_mac] -> count_old_sequence_number_transmitted
global invalid_sq_replay: table[string] of count;

# Set to hold source MAC addresses which have been found to be attack sources so far.
global attack_sources: set[string];

export {
        redef enum Notice::Type += { GOOSE_Poisoning }; 
}

function handle_replay_attack(source: string, field: string)
	{
	local field_name = "stNum";
	if ( field == "sq")
		field_name = "sqNum";
	if ( source !in attack_sources )
		{
		add attack_sources[source];
		# Generate attack-detection notice.
		NOTICE([$note=GOOSE_Poisoning,
			$msg=fmt("GOOSE replay attempt detected with invalid %s: source %s, attack stNum %d, and sqNum %d",
				field_name, source, src_state_map[source]$st, src_state_map[source]$sq)
			]);
		}
	else
		{
		# Generate attack-continuation notice.
		NOTICE([$note=GOOSE_Poisoning,
			$msg=fmt("GOOSE replay attempt continued with invalid %s: source %s, attack stNum %d, and sqNum %d",
				field_name, source, src_state_map[source]$st, src_state_map[source]$sq)
			]);
		}	
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
		invalid_st_replay[src_mac] = 0;
		invalid_sq_replay[src_mac] = 0;
		}
	else
		{
		if ( timestamp > src_state_map[src_mac]$ts )
			{
			if ( st_num > src_state_map[src_mac]$st || src_state_map[src_mac]$st == MAX_ST ) 
				{
				# Transmission of new state.
				src_state_map[src_mac] = [$ts = timestamp, $st = st_num, $sq = sq_num];
				}
			else if ( st_num == src_state_map[src_mac]$st )
				{
				# Re-transmission.
				if ( sq_num > src_state_map[src_mac]$sq || src_state_map[src_mac]$sq == MAX_SQ)
					{
					src_state_map[src_mac] = [$ts = timestamp, $st = st_num, $sq = sq_num];
					}
				else
					{
					# Invalid sqNum.
					invalid_sq_replay[src_mac] += 1;
					if ( invalid_sq_replay[src_mac] >= DETECTION_THRESHOLD )
						{
						handle_replay_attack(src_mac, "sq");
						# Reset counter.
						invalid_sq_replay[src_mac] = 0;
						src_state_map[src_mac] = [$ts = timestamp, $st = st_num, $sq = sq_num];
						}
					
					}
				}
			else # st_num < src_state_map[src_mac]$st
				{
				invalid_st_replay[src_mac] += 1;
				if ( invalid_st_replay[src_mac] >= DETECTION_THRESHOLD )
					{
					handle_replay_attack(src_mac, "st");
					# Reset counter.
					invalid_st_replay[src_mac] = 0;
					src_state_map[src_mac] = [$ts = timestamp, $st = st_num, $sq = sq_num];
					}
				}
			}
		}

        }

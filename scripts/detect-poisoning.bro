##! Detect the receipt of several old packets (retransmitted by publisher),
##! which will indicate an MITM poisoning attack.

@load base/frameworks/notice
@load policy/misc/stats

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
	redef Stats::report_interval = 3msec;
	redef enum Log::ID += { LOG_STAT };
	type LogStat: record {
		ts: time	&log; # network_time()
		curr_time: time	&log; # current_time()
		src_mac: string	&log; # Source MAC address
		dat_set: string	&log; # GOOSE dataSet
		delay: double	&log; # curr_time - ts in msec
		length: count	&log; # GOOSE length	
	};
	global log_goose_stat: event(rec: LogStat);
}

event bro_init() &priority=5
        {
		Log::create_stream(GOOSE::LOG_STAT, [$columns=LogStat, $ev=log_goose_stat, $path="goose_stat"]);	
	}

function handle_replay_attack(data_set: string, field: string)
	{
	# Generate notices given a GOOSE attack packet.
	local curr_time: time;
	local field_name = "StNum";
	if ( field == "sq")
		field_name = "SqNum";
	if ( data_set !in attack_sources )
		{
		add attack_sources[data_set];
		# Generate attack-detection notice.
		curr_time = current_time();
		NOTICE([$note=GOOSE_Poisoning,
			$msg=fmt("Curr_time %f GOOSE replay attempt detected with invalid %s: src_mac %s, data_set %s attack st_num %d, and sq_num %d",
				curr_time, field_name, src_state_map[data_set]$src, data_set, src_state_map[data_set]$st, src_state_map[data_set]$sq)
			]);
		}
	else
		{
		# Generate attack-continuation notice.
		curr_time = current_time();
		NOTICE([$note=GOOSE_Poisoning,
			$msg=fmt("Curr_time %f GOOSE replay attempt continued with invalid %s: src_mac %s, data_set %s attack st_num %d, and sq_num %d",
				curr_time, field_name, src_state_map[data_set]$src, data_set, src_state_map[data_set]$st, src_state_map[data_set]$sq)
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
	local curr_time = current_time();
	local stat_rec: LogStat;
	stat_rec$ts = timestamp;
	stat_rec$curr_time = curr_time;
	stat_rec$src_mac = src_mac;
	stat_rec$dat_set = data_set;
	stat_rec$delay = (time_to_double(curr_time) - time_to_double(timestamp)) * 1000; #msec
	# stat_rec$length = info$length;
	Log::write(LOG_STAT, stat_rec);
        }

##! This script implements base functionality for GOOSE communication.
##! It generates the goose.log and goose_stat.log.
##! It also implements the detection of GOOSE poisoning attempts,
##! which are carried out by an MITM attacker using invalid stNum and/or sqNum.
##! The detection messages are written to notice.log.

@load base/frameworks/logging
@load base/frameworks/notice
@load policy/misc/stats

module GOOSE;

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
        redef enum Log::ID += { LOG, LOG_STAT };
        redef enum Notice::Type += { GOOSE_Poisoning_Attempt };
	redef Stats::report_interval = 1.0min; # Default: 5.0min

	# GOOSE Info.
        type Info: record {
                ts: time                        &log; ## Timestamp at which the packet was captured by Bro
                src_mac: string                 &log; ## Source MAC address
                dst_mac: string                 &log; ## Destination MAC address
                gocb_ref: string                &log; ## GOOSE control block reference
                time_allowed_to_live: count     &log; ## The maximum time a receiver should wait to receive the next message
                dat_set: string                 &log; ## GOOSE datSet
                go_id: string                   &log &optional; ## Sender IED identifier
                goose_t_sec: count              &log; ## Seconds since the epoch denoting the timestamp at which the stNum was modified
                goose_t_nanosec: count          &log; ## The number of nanoseconds since the last whole second
                st_num: count                   &log; ## State number
                sq_num: count                   &log; ## Sequence number
                test: bool                      &log; ## True (T) when in test mode
                conf_rev: count                 &log; ## Configuration revision - the version of the IED
                nds_com: bool                   &log; ## True (T)  when the data in the GOOSE message is invalid
                num_dataset_entries: count      &log; ## Number of dataSet entries
                all_data_string: string         &log; ## Single string representing allData
        };
        ## Event that can be handled to access the GOOSE record as it is sent on
        ## to the logging framework.
        global log_goose: event(rec: Info);

	# GOOSE Stat.
	type Stat: record {
		ts: time	&log; ## network_time()
		curr_time: time	&log; ## current_time()
		src_mac: string	&log; ## Source MAC address
		dat_set: string	&log; ## GOOSE datSet
		delay: double	&log; ## (curr_time - ts) in msec
		length: count	&log; ## GOOSE length	
	};
        ## Event that can be handled to access the GOOSE_STAT record as it is sent on
        ## to the logging framework.
	global log_goose_stat: event(rec: Stat);

	## Maximum value that stNum can take, as configured. 
	option MAX_ST = 65535 &redef; # 2**16 - 1
	## Maximum value that sqNum can take, as configured. 
	option MAX_SQ = 65535 &redef;
	## Threshold for attack indictor:
	## number of violations more than the threshold would signify an attack.
	option DETECTION_THRESHOLD = 3 &redef;
}

event bro_init() &priority=10
        {
	Log::create_stream(GOOSE::LOG, [$columns=Info, $ev=log_goose, $path="goose"]);
	Log::create_stream(GOOSE::LOG_STAT, [$columns=Stat, $ev=log_goose_stat, $path="goose_stat"]);	
	}

function goose_data_to_string(datarray: GOOSE::SequenceOfData): string
        {
	# Convert GOOES allData to a string for logging.
        local dataStr = "";
        for (d in datarray)
                {
                local dat = datarray[d];
                if(dat?$boolVal)
                        dataStr += cat(dat$boolVal, ",");
                else if(dat?$bitStringVal)
                        {
                        dataStr += "[";
                        for(bs in dat$bitStringVal)
                                {
                                dataStr += cat(dat$bitStringVal[bs], ",");
                                }
                        dataStr += "],";
                        }
                else if(dat?$intVal)
                        dataStr += fmt("%d,", dat$intVal);
                else if(dat?$uintVal)
                        dataStr += fmt("%d,", dat$uintVal);
                else if(dat?$realVal)
                        dataStr += fmt("%f,", dat$realVal);
                else if(dat?$stringVal)
                        dataStr += fmt("%s,", dat$stringVal);
                else if(dat?$timeVal)
                        dataStr += fmt("%ds.%dns,", dat$timeVal$secondsSince1970, dat$timeVal$nanoseconds);
                else if(dat?$arrayVal)
                        {
                        dataStr += "[";
                        dataStr += goose_data_to_string(dat$arrayVal); # Recursive call
                        dataStr += "],";
                        }
                else
                        dataStr += "?,"; # Unrecognized tag
                }
        dataStr = dataStr[:-1]; # Remove trailing comma
        return dataStr;
        }

function handle_replay_attack(data_set: string, field: string)
	{
	# Generate notices given a GOOSE attack packet.
	local curr_time = current_time();
	NOTICE([$note=GOOSE_Poisoning_Attempt,
		$msg=fmt("Possible GOOSE poisoning attempt %s with invalid %s; source MAC %s, datSet %s, stNum %d, sqNum %d, detection time %f.",
			data_set in attack_sources ? "continued" : "detected",
			field == "st" ? "stNum": "sqNum",
			src_state_map[data_set]$src, data_set, src_state_map[data_set]$st, src_state_map[data_set]$sq, curr_time)
		]);
	add attack_sources[data_set];
	}

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
        {
	local net_time = network_time(); # Alternatively, info$captureTime;
	local src_mac = info$source;
	local dst_mac = info$destination;
	local data_set = pdu$datSet;
        local st_num = pdu$stNum;
        local sq_num = pdu$sqNum;
	local gocb_ref = pdu$gocbRef;

	# Write goose log.
        local rec: Info;
        rec$ts = net_time;
        rec$src_mac = src_mac;
        rec$dst_mac = dst_mac;
        rec$gocb_ref = gocb_ref;
        rec$time_allowed_to_live = pdu$timeAllowedToLive;
        rec$dat_set = data_set;
        if(pdu?$goID)
        {
                rec$go_id = pdu$goID;
        }
        rec$goose_t_sec = pdu$t$secondsSince1970;
        rec$goose_t_nanosec = pdu$t$nanoseconds;
        rec$st_num = st_num;
        rec$sq_num = sq_num;
        rec$test = pdu$test;
        rec$conf_rev = pdu$confRev;
        rec$nds_com = pdu$ndsCom;
        rec$num_dataset_entries = pdu$numDatSetEntries;
        local all_data_str = "[";
        all_data_str += goose_data_to_string(pdu$allData);
        all_data_str += "]";
        rec$all_data_string = all_data_str;
        Log::write(GOOSE::LOG, rec);

	# Attack detection.
	if ( data_set !in src_state_map )
		{
		src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = net_time, $st = st_num, $sq = sq_num];
		invalid_st_replay[data_set] = 0;
		invalid_sq_replay[data_set] = 0;
		}
	else
		{
		# Only consider the packets that are captured at a later time after the last seen packet.
		if ( net_time >= src_state_map[data_set]$ts )
			{
			if ( st_num > src_state_map[data_set]$st || src_state_map[data_set]$st == MAX_ST ) 
				{
				# Transmission of new state.
				src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = net_time, $st = st_num, $sq = sq_num];
				}
			else if ( st_num == src_state_map[data_set]$st )
				{
				# Re-transmission.
				if ( sq_num > src_state_map[data_set]$sq || src_state_map[data_set]$sq == MAX_SQ)
					{
					src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = net_time, $st = st_num, $sq = sq_num];
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
						src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = net_time, $st = st_num, $sq = sq_num];
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
					src_state_map[data_set] = [$src = src_mac, $dst = dst_mac, $ts = net_time, $st = st_num, $sq = sq_num];
					}
				}
			}
		}
	# Latency measurement and goose_stat logging.
	local curr_time = current_time();
	local stat_rec: Stat;
	stat_rec$ts = net_time;
	stat_rec$curr_time = curr_time;
	stat_rec$src_mac = src_mac;
	stat_rec$dat_set = data_set;
	stat_rec$delay = (time_to_double(curr_time) - time_to_double(net_time)) * 1000; #msec
	# stat_rec$length = info$length; # info does not have a length field yet; need to add
	Log::write(LOG_STAT, stat_rec);
        }

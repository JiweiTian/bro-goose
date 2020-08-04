##! This script implements GOOSE traffic analysis functionality.
##! It generates goose.log and goose_stats.log.
##! It also implements the detection of GOOSE poisoning and data manipulation attacks.
##! The alerts are written to notice.log.

@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/input
@load policy/misc/stats

module GOOSE;

# Globals.
# Whitelisting.
type SMAC: record {
        src_mac: string;
};
global src_mac_wl: set[string] = set();

type DMAC: record {
        dst_mac: string;
};
global dst_mac_wl: set[string] = set();

type DSET: record {
        dat_set: string;
};
global dat_set_wl: set[string] = set();

type GOCB: record {
        gocb_ref: string;
};
global gocb_ref_wl: set[string] = set();

type GOID: record {
        go_id: string;
};
global go_id_wl: set[string] = set();

# Min and Max allowed values for TAL
const MIN_TAL = 0;
const MAX_TAL = 10000;

# GOOSE poisoning.
# Record to hold attributes from a GOOSE packet.
type PacketRec: record {
	src: string;
	dst: string;
	st: count;
	sq: count;
	tal: count;
};

type PacketVec: vector of PacketRec;

global normal_state: table[string] of PacketRec = table();
global staging_state: table[string] of PacketVec = table();
global attack_state: table[string] of PacketVec = table();
global state_changed: table[string] of bool = table();
global do_sec_analysis: table[string] of bool = table();
global t_flush: table[string] of interval = table();

# Min and max values that stNum can take, as configured. 
const MIN_ST = 1;
const MAX_ST = 65535; # 2**16 - 1
# Min and max values that sqNum can take, as configured. 
const MIN_SQ = 0;
const MAX_SQ = 65535;

# Globals for physical behavior detector.
global after_fault_counter: table[string] of count = table();
global fault_seen: table[string] of bool = table();
global trip_done: table[string] of bool = table();
global cb_opened: table[string] of bool = table();
global need_fault_check: table[string] of bool = table();

global fd_st: count;
global fd_sq: count;
global fd_src: string;
global fd_ds: string;
global fd_data: string;

global ds_prefixes_all: set[string] = set("BIED100","LIED10","LIED11","LIED12","LIED20","LIED20","LIED22",
	"LIED30","LIED31","LIED32","LIED33","LIED40","LIED41","LIED42","LIED43","TIED13","TIED23");
global ds_prefixes: set[string] = set("BIED100","LIED10","LIED11","LIED12","LIED20","LIED20","LIED22");

global alarm_to_measure_ds: table[string] of string = table();
global status_to_alarm_ds: table[string] of string = table ();
global status_to_measure_ds: table[string] of string = table();
global parent_measure_ds: table[string] of string = table();
global parent_alarm_ds: table[string] of string = table();
global parent_status_ds: table[string] of string = table();

global safe_ranges: table[string] of vector of double = table();

# Functions for physical behavior detector.
function is_fault(dset: string, data: vector of double): bool {
	# Return T if there is a fault measurement in LIED10 or LIED11.
	local v1min = safe_ranges[dset][0] - 5.0;
	local v1max = safe_ranges[dset][1] + 5.0;
	local v2min = safe_ranges[dset][2] - 50.0;
	local v2max = safe_ranges[dset][3] + 50.0;
	local v3min = safe_ranges[dset][4] - 5000.0;
	local v3max = safe_ranges[dset][5] + 5000.0;
	local v4min = safe_ranges[dset][6] - 500.0;
	local v4max = safe_ranges[dset][7] + 500.0;
	local v5min = safe_ranges[dset][8] - 0.5;
	local v5max = safe_ranges[dset][9] + 0.5;
	local v6min = safe_ranges[dset][10] - 0.05;
	local v6max = safe_ranges[dset][11] + 0.05;

	if ( data[0]<v1min || data[0]>v1max || data[1]<v1min || data[1]>v1max || data[2]<v1min || data[2]>v1max ||
		data[3]<v2min || data[3]>v2max || data[4]<v2min || data[4]>v2max || data[5]<v2min || data[5]>v2max ||
		data[6]<v3min || data[6]>v3max ||
		data[7]<v4min || data[7]>v4max ||
		data[8]<v5min || data[8]>v5max ||
		data[9]<v6min || data[9]>v6max )
		return T;
	return F;
}

function is_trip(data: vector of int): bool {
	# Return T if the alarm all_data has True in first place.
	if ( data[0] == 1 )
		return T;
	return F;
}
function is_open(data: vector of int): bool {
	# Return T if CB is open: i.e., status all_data has 0 in first place.
	if ( data[0] == 0 )
		return T;
	return F;
}
function vectorize_m(data: string): vector of double {
	# Return a vector of double, generated from a string of measurements.
	local vec_d: vector of double = vector();
	local vec_str = split_string(data, /,/);
	for (i in vec_str)
		vec_d[|vec_d|] = to_double(vec_str[i]);
	return vec_d;
}

function vectorize_a(data: string): vector of int {
	# Return a vector of double, generated from a string of alarms, e.g., 'F,1,F,F,F'.
	local vec_d: vector of int = vector();
	local vec_str = split_string(data, /,/);
	for (i in vec_str) {
		if (vec_str[i] == "F")
			vec_d[|vec_d|] = 0;
		else if (vec_str[i] == "T")
			vec_d[|vec_d|] = 1;
		else
			vec_d[|vec_d|] = to_int(vec_str[i]);
	}
	return vec_d;
}

function vectorize_s(data: string): vector of int {
	# Return a vector of double, generated from a string of status, e.g., '1,1,0,1,F'.
	local vec_d: vector of int = vector();
	local vec_str = split_string(data, /,/);
	for (i in vec_str) {
		if (vec_str[i] == "F")
			vec_d[|vec_d|] = 0;
		else if (vec_str[i] == "T")
			vec_d[|vec_d|] = 1;
		else
			vec_d[|vec_d|] = to_int(vec_str[i]);
	}
	return vec_d;
}

# The export block.
export {
        redef enum Log::ID += { LOG, LOG_STATS };
        redef enum Notice::Type += { GOOSE_Poisoning, GOOSE_False_Data_Injection, GOOSE_Bad_Semantics, GOOSE_Unauthorized_Access, GOOSE_Anomaly };
	redef Stats::report_interval = 1.0sec; # Default: 5.0min

	# GOOSE Info.
        type Info: record {
                ts: time                        &log; # Timestamp at which the packet was captured by Bro
                src_mac: string                 &log; # Source MAC address
                dst_mac: string                 &log; # Destination MAC address
                gocb_ref: string                &log; # GOOSE control block reference
                time_allowed_to_live: count     &log; # The maximum time a receiver should wait to receive the next message
                dat_set: string                 &log; # GOOSE datSet
                go_id: string                   &log &optional; # Sender IED identifier
                goose_t: string              	&log; # Seconds.nanoseconds since the epoch denoting the timestamp at which the stNum was modified
                st_num: count                   &log; # State number
                sq_num: count                   &log; # Sequence number
                test: bool                      &log; # True (T) when in test mode
                conf_rev: count                 &log; # Configuration revision - the version of the IED
                nds_com: bool                   &log; # True (T)  when the data in the GOOSE message is invalid
                num_dataset_entries: count      &log; # Number of dataSet entries
                all_data_string: string         &log; # Single string representing allData
        };
        # Event that can be handled to access the GOOSE record as it is sent to logging framework.
        global log_goose: event(rec: Info);

	# GOOSE Stat.
	type Stat: record {
		ts:time 		&log; # network_time()
		src_mac: string 	&log; # Source MAC address
		dat_set: string		&log; # GOOSE datSet
		goose_entry_time:time 	&log; # current_time() at the start of goose_message()
		goose_exit_time: time 	&log; # current_time() at the end of goose_message()
		goose_latency: double	&log; # (goose_exit_time - goose_entry_time) in msec
		length: count		&log; # GOOSE length	
	};
        # Event that can be handled to access the GOOSE_STATS record as it is sent to logging framework.
	global log_goose_stats: event(rec: Stat);
}

# Initialize whitelists before they are checked.
event bro_init() &priority=20 {
	# Reading the whitelisting files.
	Input::add_table([$source="/usr/local/bro/share/bro/site/whitelist_src_mac.txt", $name="src_mac_wl", $idx=SMAC, $destination=src_mac_wl]);
	Input::remove("src_mac_wl");
	Input::add_table([$source="/usr/local/bro/share/bro/site/whitelist_dst_mac.txt", $name="dst_mac_wl", $idx=DMAC, $destination=dst_mac_wl]);
	Input::remove("dst_mac_wl");
	Input::add_table([$source="/usr/local/bro/share/bro/site/whitelist_dat_set.txt", $name="dat_set_wl", $idx=DSET, $destination=dat_set_wl]);
	Input::remove("dat_set_wl");
	Input::add_table([$source="/usr/local/bro/share/bro/site/whitelist_gocb_ref.txt", $name="gocb_ref_wl", $idx=GOCB, $destination=gocb_ref_wl]);
	Input::remove("gocb_ref_wl");
	Input::add_table([$source="/usr/local/bro/share/bro/site/whitelist_go_id.txt", $name="go_id_wl", $idx=GOID, $destination=go_id_wl]);
	Input::remove("go_id_wl");
}

event bro_init() &priority=15 {
	Log::create_stream(GOOSE::LOG, [$columns=Info, $ev=log_goose, $path="goose"]);
	Log::create_stream(GOOSE::LOG_STATS, [$columns=Stat, $ev=log_goose_stats, $path="goose_stats"]);	


	# Phsycial behavior initializations.
	for (pfx in ds_prefixes_all) {
		local mds = pfx+"MEAS/LLN0$Measurement";
		local ads = pfx+"PROT/LLN0$Alarm";
		local sds = pfx+"CTRL/LLN0$Status";

		after_fault_counter[mds] = 0;
		after_fault_counter[ads] = 0;
		after_fault_counter[sds] = 0;
		need_fault_check[mds] = T;
		fault_seen[mds] = F;
		cb_opened[sds] = F;
		trip_done[ads] = F;
		alarm_to_measure_ds[ads] = mds;
		status_to_alarm_ds[sds] = ads;
		status_to_measure_ds[sds] = mds;
		safe_ranges[mds] = vector(305.0, 315.0, 38090.0, 38120.0, 29998000.0, 30001992.0, 18498006.0, 18501997.0, 49.950001, 50.049999, 0.83, 0.87);
	}
	parent_alarm_ds["LIED11PROT/LLN0$Alarm"] = "LIED10PROT/LLN0$Alarm";
	parent_alarm_ds["LIED22PROT/LLN0$Alarm"] = "LIED20PROT/LLN0$Alarm";
	parent_status_ds["LIED11CTRL/LLN0$Status"] = "LIED10CTRL/LLN0$Status";
	parent_status_ds["LIED22CTRL/LLN0$Status"] = "LIED20CTRL/LLN0$Status";
	
	safe_ranges["LIED10MEAS/LLN0$Measurement"] = vector(305.0, 315.0, 38090.0, 38120.0, 29998000.0, 30001992.0, 18498006.0, 18501997.0, 49.950001, 50.049999, 0.83, 0.87);
	safe_ranges["LIED11MEAS/LLN0$Measurement"] = vector(305.0, 315.0, 38090.0, 38120.0, 29998008.0, 30001997.0, 18498002.0, 18501967.0, 49.950001, 50.049999, 0.83, 0.87);
	safe_ranges["LIED20MEAS/LLN0$Measurement"] = vector(305.0, 315.0, 38090.0, 38120.0, 29998014.0, 30001995.0, 18498000.0, 18501998.0, 49.950001, 50.049999, 0.83, 0.87);
	safe_ranges["LIED22MEAS/LLN0$Measurement"] = vector(305.0, 315.0, 38090.0, 38120.0, 29998014.0, 30001995.0, 18498000.0, 18501998.0, 49.950001, 50.049999, 0.83, 0.87);

}

function goose_data_to_string(datarray: GOOSE::SequenceOfData): string {
	# Convert GOOES allData to a string for logging.
        local dataStr = "";
        for (d in datarray) {
                local dat = datarray[d];
                if(dat?$boolVal)
                        dataStr += cat(dat$boolVal, ",");
                else if(dat?$bitStringVal) {
                        dataStr += "[";
                        for(bs in dat$bitStringVal)
                                dataStr += cat(dat$bitStringVal[bs], ",");
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
                else if(dat?$arrayVal) {
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

function generate_notice(notice_type: string, message: string) {
	# Generate a notice log.
	switch notice_type {
		case "poisoning_attack":
			NOTICE([$note=GOOSE_Poisoning, $msg=message]);
			break;
		case "data_attack":
			NOTICE([$note=GOOSE_False_Data_Injection, $msg=message]);
			break;
		case "semantic_attack":
			NOTICE([$note=GOOSE_Bad_Semantics, $msg=message]);
			break;
		case "access_attack":
			NOTICE([$note=GOOSE_Unauthorized_Access, $msg=message]);
			break;
		case "anomaly":
			NOTICE([$note=GOOSE_Anomaly, $msg=message]);
			break;
	}
}

# GOOSE Poisoning related events and functions.
event flush_staging(my_ds: string) {
	if ( |attack_state[my_ds]| > 0 ) {
		# Nothing to flush.
		do_sec_analysis[my_ds] = F;
		return;
	}
	# Flushing the staging state.
	if (|staging_state[my_ds]| >= 2) {
		normal_state[my_ds] = staging_state[my_ds][|staging_state[my_ds]|-2];
		t_flush[my_ds] = double_to_interval(staging_state[my_ds][|staging_state[my_ds]|-2]$tal / 1000.0);
		staging_state[my_ds] = vector(staging_state[my_ds][|staging_state[my_ds]|-1]);
	}
	schedule t_flush[my_ds] { flush_staging(my_ds) };
}
# Functions for checking the values of stNum and sqNum w.r.t. the current state of the communication.
function next_expected_sq(st: count, sq: count, dset: string): bool {
	local chain = staging_state[dset];
	local last_idx = |chain| - 1;
	if ( (st == chain[last_idx]$st && sq == chain[last_idx]$sq + 1) || (st == chain[last_idx]$st && chain[last_idx]$sq == MAX_SQ && sq == MIN_SQ) )
		return T;
	return F;
}

function next_expected_st(st: count, sq: count, dset: string): bool {
	local chain = staging_state[dset];
	local last_idx = |chain| - 1;
	if ( (st == chain[last_idx]$st+1 && sq == MIN_SQ) || (chain[last_idx]$st==MAX_ST && st==MIN_ST) )
		return T;
	return F;
}
function already_present(st: count, sq: count, dset: string): int {
	# Returns the index of already present item. -1 if not present.
	local chain = staging_state[dset];
	for (i in chain) {
		if (st==chain[i]$st && sq==chain[i]$sq)
			return i;
	}
	return -1;
}

function prev_state_recurred(st: count, sq: count, dset: string): bool {
	local schain = staging_state[dset];
	local nrec = normal_state[dset];
	if (st==nrec$st && sq==nrec$sq+1)
		return T;
	for (i in schain) {
		if (st==schain[i]$st && sq==schain[i]$sq+1)
			return T;
	}
	return F;
}

function high_sq(st: count, sq: count, dset: string): bool {
	local chain = staging_state[dset];
	if ( st==chain[|chain|-1]$st && sq>chain[|chain|-1]$sq+1 )
		return T;
	return F;
}

function high_st(st: count, sq: count, dset: string): bool {
	local chain = staging_state[dset];
	if ( st>chain[|chain|-1]$st+1 )
		return T;
	return F;
}

# Main event that handles a GOOSE message. 
event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU) &priority=-20 {
	local entry_time = current_time();
	local net_time = network_time(); # alternatively, info$captureTime;
	local src_mac = info$source;
	local dst_mac = info$destination;
	local TAL = pdu$timeAllowedToLive;
	local data_set = pdu$datSet;
	local goose_t_double = pdu$t$secondsSince1970 + pdu$t$nanoseconds;
        local st_num = pdu$stNum;
        local sq_num = pdu$sqNum;

	# Write goose log.
        local rec: Info;
        rec$ts = network_time();
        rec$src_mac = src_mac;
        rec$dst_mac = dst_mac;
        rec$gocb_ref = pdu$gocbRef; 
        rec$time_allowed_to_live = TAL;
        rec$dat_set = data_set;
        if(pdu?$goID)
                rec$go_id = pdu$goID;
        rec$goose_t = fmt("%d.%d", pdu$t$secondsSince1970, pdu$t$nanoseconds);
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

	# START 1
	# 1. Protocol Semantics.
	# 1.1 Length validation: todo.
	# Currently pdu does not have a 'length' field. We will need to add that to analyzer and check it against 'l2_hdr$len'.

	# 1.2 TAL validation
	if ( TAL<MIN_TAL || TAL > MAX_TAL)
		generate_notice("semantic_attack", fmt("Injection of a packet with bad TAL: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, TAL=%d, detectionTime= %f",
			st_num, sq_num, src_mac, data_set, TAL, current_time()));
	# 1.3 T validation
	# Done inside next_sq() and next_st()
	# END 1
	
	# START 2
	# 2. Whitelisting.
	if ( src_mac !in src_mac_wl )
		generate_notice("access_attack", fmt("Injection of a packet with unknown srcMAC: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, detectionTime= %f",
			st_num, sq_num, src_mac, data_set, current_time()));
	if ( dst_mac !in dst_mac_wl )
		generate_notice("access_attack", fmt("Injection of a packet with unknown dstMAC: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, dst_mac=%s, detectionTime= %f",
			st_num, sq_num, src_mac, data_set, dst_mac, current_time()));
	if ( data_set !in dat_set_wl )
		generate_notice("access_attack", fmt("Injection of a packet with unknown datSet: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, detectionTime= %f",
			st_num, sq_num, src_mac, data_set, current_time()));
	if ( pdu$gocbRef !in gocb_ref_wl )
		generate_notice("access_attack", fmt("Injection of a packet with unknown gocbRef: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, gocbRef=%s, detectionTime= %f",
			st_num, sq_num, src_mac, data_set, pdu$gocbRef, current_time()));
	if(pdu?$goID)
		if ( pdu$goID !in go_id_wl )
			generate_notice("access_attack", fmt("Injection of a packet with unknown goID: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, goID=%s, detectionTime= %f",
				st_num, sq_num, src_mac, data_set, pdu$goID, current_time()));
	# Todo: implement pair whitelisting for: (srcMAC, datSet) and (datSet, numDatSetEntries).
	# END 2

	# START 3
	# 3. Poisoning Attack detection.
	# Initialize normal and staging states with one packet in each.
	# Thus, we are assuming that the first two packets are normal.
	if ( data_set !in normal_state ) {
		# Initialize global variables for a new data_set.
		normal_state[data_set] = [$src=src_mac, $dst=dst_mac, $st=st_num, $sq=sq_num, $tal=TAL];
		staging_state[data_set] = vector();
		attack_state[data_set] = vector();
		do_sec_analysis[data_set] = T;
		state_changed[data_set] = F;
		t_flush[data_set] = double_to_interval(TAL / 1000.0); # sec
	}
	else if ( |staging_state[data_set]|==0 ) { # means normal_state[data_set] is True.
		staging_state[data_set] = vector([$src=src_mac, $dst=dst_mac, $st=st_num, $sq=sq_num, $tal=TAL]);
		schedule t_flush[data_set] { flush_staging(data_set) };
	}
	else if ( do_sec_analysis[data_set] ) {
		# Program comes here when both normal and staging states have at least one item each.
		local this_pkt: PacketRec = [$src=src_mac, $dst=dst_mac, $st=st_num, $sq=sq_num, $tal=TAL];
		# Checks for st_num and sq_num.
		if ( next_expected_sq(st_num, sq_num, data_set) ) {
			staging_state[data_set][|staging_state[data_set]|] = this_pkt;
			# Note: we will need to set this F at some point.., may be in the flush_staging.
			#state_changed[data_set] = F;
		} #end if 'next_expected_sq
		else if ( next_expected_st(st_num, sq_num, data_set) ) {
			state_changed[data_set] = T;
			staging_state[data_set][|staging_state[data_set]|] = this_pkt;
		} #end else if 'next_expected_st
		else if ( already_present(st_num, sq_num, data_set) >= 0 ) {
			local match_idx = already_present(st_num, sq_num, data_set);
			generate_notice("poisoning_attack", fmt("Injection of a packet with expected numbers: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, detectionTime= %f",
				staging_state[data_set][match_idx]$st, staging_state[data_set][match_idx]$sq, src_mac, data_set, current_time()));
			attack_state[data_set][|attack_state[data_set]|] = staging_state[data_set][match_idx];
			# Uncomment below to stop security analysis after an attack is found and alerted.
			#do_sec_analysis[data_set] = F;
			# We instead reset the state and restart the sec. analysis.
			normal_state = table();
		} # end else if 'already_present' 
		else if ( state_changed[data_set] && prev_state_recurred(st_num, sq_num, data_set) ) {
        		# Violation occurred is actually the whole staging + attack
			generate_notice("poisoning_attack", fmt("Previous state recurred: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, detectionTime= %f",
				st_num, sq_num, src_mac, data_set, current_time()));
			attack_state[data_set][|attack_state[data_set]|] = this_pkt;
			# Uncomment below to stop security analysis after an attack is found and alerted.
			#do_sec_analysis[data_set] = F;
			# We instead reset the state and restart the sec. analysis.
			normal_state = table();
		} # end else if
		else if ( high_sq(st_num, sq_num, data_set) ) {
			generate_notice("poisoning_attack", fmt("Injection of a packet with high sqNum: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, detectionTime= %f",
				st_num, sq_num, src_mac, data_set, current_time()));
        		attack_state[data_set][|attack_state[data_set]|] = this_pkt;
			# Uncomment below to stop security analysis after an attack is found and alerted.
			#do_sec_analysis[data_set] = F;
			# We instead reset the state and restart the sec. analysis.
			normal_state = table();
		} # end else if 'high_sq'
		else if ( high_st(st_num, sq_num, data_set) ) {
			generate_notice("poisoning_attack", fmt("Injection of a packet with high stNum: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, detectionTime= %f",
				st_num, sq_num, src_mac, data_set, current_time()));
			attack_state[data_set][|attack_state[data_set]|] = this_pkt;
			# Uncomment below to stop security analysis after an attack is found and alerted.
			#do_sec_analysis[data_set] = F;
			# We instead reset the state and restart the sec. analysis.
			normal_state = table();
		} # end else if 'high_st'
		#else {
		#	# Anomalous values of st_num or sq_num, but not malicious.
		#	# These are mostly the packets with old counters, that the subscriber will ignore.
		#	generate_notice("anomaly", fmt("Anomalous pakcet: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, detectionTime= %f",
		#		st_num, sq_num, src_mac, data_set, current_time()));
		#} # end else

	} # endif (do_sec_analysis)
	else
		print fmt("skipping security analysis for %s", data_set);;
	# END 3
	
	# START 4
	# 4. Physical behavior detector.
	# Data checks
	# Range validation
	# Correlation rules.

	# For cases when fault occurs first and we check the response of devices after that.
	local dset_pfx = data_set[:6];
	if ( "Measurement" in data_set && dset_pfx in ds_prefixes_all ) { # && !LIED10_detection_done) {
		if (need_fault_check[data_set]) {
			if ( !fault_seen[data_set] ) {
				#local data_str1 = goose_data_to_string(pdu$allData);
				local m_vec1 = vectorize_m(goose_data_to_string(pdu$allData));
				if ( is_fault(data_set, m_vec1) ) {
					after_fault_counter[data_set] = 1;
					fault_seen[data_set] = T;
					fd_st = st_num;
					fd_sq = sq_num;
					fd_src = src_mac;
					fd_ds = data_set;
					fd_data = all_data_str;
				}
			}
			else
				after_fault_counter[data_set] = after_fault_counter[data_set] + 1;
		}
	}
	else if ( "Alarm" in data_set && dset_pfx in ds_prefixes_all ) { # && !LIED10_detection_done) {
		local a_vec1 = vectorize_a(goose_data_to_string(pdu$allData));
		if ( is_trip(a_vec1) ) {
			trip_done[data_set] = T;
			if (fault_seen[alarm_to_measure_ds[data_set]]) {
				need_fault_check[alarm_to_measure_ds[data_set]] = F; # this is benign trip
				#LIED10_detection_done = T;
			}
			else {
				after_fault_counter[data_set] = 1;
				fd_st = st_num;
				fd_sq = sq_num;
				fd_src = src_mac;
				fd_ds = data_set;
				fd_data = all_data_str;
			}
		}
		else if (trip_done[data_set])
			after_fault_counter[data_set] = after_fault_counter[data_set] + 1;
		
	}
	else if ( "Status" in data_set && dset_pfx in ds_prefixes_all ) { # && !LIED10_detection_done) {
		local s_vec1 = vectorize_s(goose_data_to_string(pdu$allData));
		if ( is_open(s_vec1) ) {
			cb_opened[data_set] = T;
			if (fault_seen[status_to_measure_ds[data_set]] || trip_done[status_to_alarm_ds[data_set]]) {
				need_fault_check[status_to_measure_ds[data_set]] = F; # this is benign open
				#LIED10_detection_done = T;
			}
			else {
				after_fault_counter[data_set] = 1;
				fd_st = st_num;
				fd_sq = sq_num;
				fd_src = src_mac;
				fd_ds = data_set;
				fd_data = all_data_str;
			}
		}
		else if(cb_opened[data_set])
			after_fault_counter[data_set] = after_fault_counter[data_set] + 1;
	}

	# We only check the violation for a short list of IEDs since we haven't learned the safe ranges for all yet.
	# Future work: complete learning for all IEDs.
	for ( pfx in ds_prefixes ) {
		if ( after_fault_counter[pfx+"MEAS/LLN0$Measurement"]>2 || after_fault_counter[pfx+"PROT/LLN0$Alarm"]>2 || after_fault_counter[pfx+"CTRL/LLN0$Status"]>2) {
			# Attack.
			generate_notice("data_attack", fmt("False data injection attack: stNum=%d, sqNum=%d, srcMAC=%s, datSet=%s, allData=%s, detectionTime= %f",
				fd_st, fd_sq, fd_src, fd_ds, fd_data, current_time()));
			#LIED10_detection_done = T;
			# Reset the globals to restart the check.
			after_fault_counter[pfx+"MEAS/LLN0$Measurement"] = 0;
			after_fault_counter[pfx+"CTRL/LLN0$Status"] = 0;
			after_fault_counter[pfx+"PROT/LLN0$Alarm"] = 0;
			fault_seen[pfx+"MEAS/LLN0$Measurement"] = F;
			cb_opened[pfx+"CTRL/LLN0$Status"] = F;
			trip_done[pfx+"PROT/LLN0$Alarm"] = F;
			need_fault_check[pfx+"MEAS/LLN0$Measurement"] = T;
		}
	}
	# END 4

	# Latency measurement and goose_stat logging.
	local stats_rec: Stat;
	stats_rec$ts = network_time();
	stats_rec$src_mac = src_mac;
	stats_rec$dat_set = data_set;
	stats_rec$goose_entry_time = entry_time;
	local exit_time = current_time();
	stats_rec$goose_exit_time = exit_time;
	# goose_latency denotes the time taken to handle goose_message() event.
	stats_rec$goose_latency = (time_to_double(exit_time)-time_to_double(entry_time)) * 1000; #msec
	# stats_rec$length = info$length; # info does not have a length field yet; need to add
	Log::write(LOG_STATS, stats_rec);

	# Print to stdout.log, the extra time that we need to account for for correctness.
	print current_time()-exit_time;
}

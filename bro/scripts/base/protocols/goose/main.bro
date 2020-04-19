##! Implements base functionality for GOOSE analysis.
##! Generates the goose.log file.

module GOOSE;

export {
	## The different types of data that a GOOSE::Data can hold, as
	## described in the IEC 61850. It will be referred as the
	## "official type".
	const GOOSE_DATA_TYPE_ARRAY: count = 0x81;
	const GOOSE_DATA_TYPE_STRUCTURE: count = 0x82;
	const GOOSE_DATA_TYPE_BOOLEAN: count = 0x83;
	const GOOSE_DATA_TYPE_BIT_STRING: count = 0x84;
	const GOOSE_DATA_TYPE_INTEGER: count = 0x85;
	const GOOSE_DATA_TYPE_UNSIGNED: count = 0x86;
	const GOOSE_DATA_TYPE_FLOATING_POINT: count = 0x87;
	const GOOSE_DATA_TYPE_REAL: count = 0x88;
	const GOOSE_DATA_TYPE_OCTET_STRING: count = 0x89;
	const GOOSE_DATA_TYPE_VISIBLE_STRING: count = 0x8a;
	const GOOSE_DATA_TYPE_BINARY_TIME: count = 0x8c;
	const GOOSE_DATA_TYPE_BCD: count = 0x8d;
	const GOOSE_DATA_TYPE_BOOLEAN_ARRAY: count = 0x8e;
	const GOOSE_DATA_TYPE_OBJ_ID: count = 0x8f;
	const GOOSE_DATA_TYPE_MMS_STRING: count = 0x90;
	const GOOSE_DATA_TYPE_UTC_TIME: count = 0x91;
}

export {
        redef enum Log::ID += { LOG, LOG_DATA };

        type LogInfo: record {
                ts: time 	   		&log; ## Timestamp at which the packet was captured by Bro
		src_mac: string             	&log; ## Source MAC address
		dst_mac: string			&log; ## Destination MAC address
                gocb_ref: string		&log; ## GOOSE control block reference
                time_allowed_to_live: count	&log; ## The maximum time a receiver should wait to receive the next message
		dat_set: string			&log; ## GOOSE dataSet
                go_id: string			&log &optional; ## Sender IED identifier
                goose_t_sec: count		&log; ## Seconds since the epoch denoting the timestamp at which the stNum was modified
                goose_t_nanosec: count		&log; ## The number of nanoseconds since the last whole second
                st_num: count			&log; ## State number
                sq_num: count			&log; ## Sequence number
                test: bool			&log; ## True (T) when in test mode
                conf_rev: count 		&log; ## Configuration revision - the version of the IED
                nds_com: bool	 		&log; ## True (T)  when the data in the GOOSE message is invalid
	};
        ## Event that can be handled to access the GOOSE record as it is sent on
	## to the logging framework.
	global log_goose: event(rec: LogInfo);

        type LogData: record {
                ts: time 	   		&log; ## Timestamp at which the packet was captured by Bro
		src_mac: string			&log; ## Source MAC address
                dst_mac: string     		&log; ## Destination MAC address
		gocb_ref: string                &log; ## GOOSE control block reference	
		dat_set: string			&log; ## GOOSE dataSet
		st_num: count                   &log; ## State number
                sq_num: count                   &log; ## Sequence number
		num_dataset_entries: count      &log; ## Number of dataSet entries
		all_data_string: string 	&log; ## Single string representing allData
        };
        ## Event that will be handled to access the GOOSE data,
        ## as a GOOSE record is sent to the logging framework.
        global log_goose_data: event(rec: LogData);
	

}

event bro_init() &priority=5
	{
	Log::create_stream(GOOSE::LOG, [$columns=LogInfo, $ev=log_goose, $path="goose"]);
	Log::create_stream(GOOSE::LOG_DATA, [$columns=LogData, $ev=log_goose_data, $path="goose_data"]);
	}

function goose_data_to_string(datarray: GOOSE::SequenceOfData): string
        {
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
                        # Recursive call :
                        dataStr += goose_data_to_string(dat$arrayVal);
			dataStr += "],";
                        }
                else
			dataStr += "?,"; # Unrecognized tag
                }
	dataStr = dataStr[:-1]; # Remove trailing comma
	return dataStr;
        }

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
        {
        # Write goose log.
        local rec: LogInfo;
        rec$ts = network_time();
        rec$src_mac = info$source;
        rec$dst_mac = info$destination;
        rec$gocb_ref = pdu$gocbRef;
        rec$time_allowed_to_live = pdu$timeAllowedToLive;
	rec$dat_set = pdu$datSet;
	if(pdu?$goID)
	{
                rec$go_id = pdu$goID;
        }
        rec$goose_t_sec = pdu$t$secondsSince1970;
        rec$goose_t_nanosec = pdu$t$nanoseconds;
        rec$st_num = pdu$stNum;
        rec$sq_num = pdu$sqNum;
        rec$test = pdu$test;
        rec$conf_rev = pdu$confRev;
        rec$nds_com = pdu$ndsCom;
        Log::write(GOOSE::LOG, rec);

	# Write goose_data log.
	local data_rec: LogData;
	data_rec$ts = network_time();
	data_rec$src_mac = info$source;
	data_rec$dst_mac = info$destination;
	data_rec$gocb_ref = pdu$gocbRef;
	data_rec$dat_set = pdu$datSet;
	data_rec$st_num = pdu$stNum;
	data_rec$sq_num = pdu$sqNum;
	data_rec$num_dataset_entries = pdu$numDatSetEntries;
	local all_data_str = "[";
	all_data_str += goose_data_to_string(pdu$allData);
	all_data_str += "]";
	data_rec$all_data_string = all_data_str;
	Log::write(LOG_DATA, data_rec);
        }

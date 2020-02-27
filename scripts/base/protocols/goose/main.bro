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
        redef enum Log::ID += { LOG };

        type LogInfo: record {
		src: string             	&log; ## Source MAC address
		dst: string			&log; ## Destination MAC address
		capture_time: double    	&log; ## Time in seconds at which the GOOSE packet was captured 
                ts_sec: count			&log; ## Seconds since the epoch denoting the timestamp at which the stNum was modified
                ts_nanosec: count		&log; ## The number of nanoseconds since the last whole second
                time_allowed_to_live: count	&log; ## The maximum time a receiver should wait to receive the next message
                gocb_ref: string		&log; ## GOOSE control block reference
                go_id: string			&log &optional; ## Sender IED identifier
                st_num: count			&log; ## The state number: this number is assigned whenever a GOOSE message is generated as a result of event change
                sq_num: count			&log; ## The sequence number: this number is assigned in increasing order to retransmitted GOOSE messages
                test: bool			&log; ## This is true (T) when in test mode
                nds_com: bool	 		&log; ## This is true (T)  when the data in the GOOSE message is invalid
                conf_rev: count 		&log; ## Configuration revision - the version of the IED
                num_dataset_entries: count	&log; ## Number of dataset entries - indicates the number of data present in the received GOOSE message
	};

        ## Event that can be handled to access the GOOSE record as it is sent on
	## to the logging framework.
	global log_goose: event(rec: LogInfo);

}

event bro_init() &priority=5
	{
	Log::create_stream(GOOSE::LOG, [$columns=LogInfo, $ev=log_goose, $path="goose"]);
	}

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
        {
        local rec: LogInfo;

        rec$src = info$source;
        rec$dst = info$destination;
        rec$capture_time = info$captureTime;

        rec$ts_sec = pdu$t$secondsSince1970;
        rec$ts_nanosec = pdu$t$nanoseconds;
        rec$time_allowed_to_live = pdu$timeAllowedToLive;
        rec$gocb_ref = pdu$gocbRef;
	if(pdu?$goID)
	{
                rec$go_id = pdu$goID;
        }
        rec$st_num = pdu$stNum;
        rec$sq_num = pdu$sqNum;
        rec$test = pdu$test;
        rec$nds_com = pdu$ndsCom;
        rec$conf_rev = pdu$confRev;
        rec$num_dataset_entries = pdu$numDatSetEntries;
        # Write this entry to the goose log
        Log::write(GOOSE::LOG, rec);
        }

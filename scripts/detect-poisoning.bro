##! Detect the receipt of several old packets (retransmitted by publisher),
##! which will indicate an MITM poisoning attack.

@load base/frameworks/notice

module GOOSE;

global last_st_num = 0;
global old_pkt_count = 0;
## Number of packets received with old sqNum that signifies an attack.
global detection_threshold = 3;

export {
	# redef enum Log::ID += { LOG_NOTICE };
	# type NoticeInfo: record {
	# 	st_num: count			&log; ## The state number: this number is assigned whenever a GOOSE message is generated as a result of event change
        # };
        redef enum Notice::Type += { GOOSE_Poisoning }; 
        global log_goose_poisoning:event(rec: NoticeInfo);
}

# event bro_init() &priority=5
# 	{
# 	Log::create_stream(GOOSE::LOG_NOTICE, [$columns=NoticeInfo, $path="goose_notice"]);
# 	}

function detect_old_packets(stNum: count, sqNum: count): bool
        {
        if ( stNum < last_st_num )
                {
                old_pkt_count += 1;
                if ( old_pkt_count > detection_threshold )
                        {
                        old_pkt_count = 0;
                        return T;
                        }
                else
                        return F;
                }
         last_st_num = stNum;
         #return T;
        #return stNum;
        }

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
        {
        local currSt = pdu$stNum;
        local currSq = pdu$sqNum; 

        # detect_old_packets(currSt, currSq);

        local rec: NoticeInfo;
        rec$st_num = pdu$stNum;
        # Log::write(GOOSE::LOG_NOTICE, rec);
        NOTICE([$note=GOOSE_Poisoning,
                $msg=fmt("GOOSE poisoning attempt start stNum %d sqNum %d. Start timestamp %s. Source is %s.  Destination is %s.", 
		        pdu$stNum, pdu$sqNum, info$captureTime, info$source, info$destination)
                ]);
        }

##! Detect the receipt of several old packets (retransmitted by publisher),
##! which will indicate an MITM poisoning attack.

@load base/frameworks/notice

module GOOSE;

global latest_st_num = 0;
global bad_pkt_count = 0;
## Number of packets received with old sqNum that signifies an attack.
global detection_threshold = 3;

export {
        redef enum Notice::Type += { GOOSE_Poisoning }; 
}

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
        {
        local st_num = pdu$stNum;
        local sq_num = pdu$sqNum;
        if ( st_num >= latest_st_num )
		{
		latest_st_num = st_num;
		}
	else
		{
		bad_pkt_count += 1;
		if ( bad_pkt_count >= 3 )
			{
			# Raise notice.
			NOTICE([$note=GOOSE_Poisoning,
                        	$msg=fmt("GOOSE poisoning attempt start stNum %d sqNum %d. Start timestamp %s. Source is %s.  Destination is %s.",
                                	pdu$stNum, pdu$sqNum, info$captureTime, info$source, info$destination)
                        	]);
			bad_pkt_count = 0;
			}
		}

        }

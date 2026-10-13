##! Interim conn.log records for long-running connections.
##!
##! Zeek normally logs a connection only when it ends. A bulk transfer that lasts the whole
##! capture (and keeps going while tcpreplay loops) would therefore never be logged. Each time
##! either side has sent another `long_conn_step` bytes, write the connection's current state to
##! conn.log (same uid, growing byte counts) - the approach of Corelight's long-connections package.
##!
##! Declared inside module Conn because Conn::set_conn() is not exported.

module Conn;

## Emit an interim record every time a direction crosses another multiple of this many bytes.
const long_conn_step: count = 5000000 &redef;

event new_connection(c: connection)
	{
	ConnThreshold::set_bytes_threshold(c, long_conn_step, T);
	ConnThreshold::set_bytes_threshold(c, long_conn_step, F);
	}

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	# refresh c$conn: identity (eoc=F) + bytes/duration/state/history (eoc=T only copies fields,
	# it does not end the connection - the final record is still logged when it closes)
	set_conn(c, F);
	set_conn(c, T);
	Log::write(Conn::LOG, c$conn);
	ConnThreshold::set_bytes_threshold(c, threshold + long_conn_step, is_orig);
	}

##! Site policy for the SIEM optimization demo.

# Write JSON logs with flat field names (id_orig_h instead of id.orig_h).
redef LogAscii::use_json = T;
redef Log::default_scope_sep = "_";

# The replayed capture comes from a 192.168.1.0/24 home/office network.
redef Site::local_nets += { 192.168.1.0/24 };

# Rotate every 10 minutes and delete rotated files (Fluent Bit has already shipped them),
# so the laptop disk does not fill up while the pcap loops.
redef Log::default_rotation_interval = 10 min;
redef Log::default_rotation_postprocessor_cmd = "/opt/demo/rotate-delete.sh";

# Interim records for long-running connections (the 55 MB transfer never ends while the pcap loops).
@load ./long-connections

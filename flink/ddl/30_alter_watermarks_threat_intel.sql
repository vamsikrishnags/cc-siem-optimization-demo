-- Reference data arrives in a burst and then goes quiet; use a tight watermark so the
-- temporal joins never wait on it (idle partitions are skipped via sql.tables.scan.idle-timeout).
ALTER TABLE `threat_intel` MODIFY WATERMARK FOR `$rowtime` AS `$rowtime` - INTERVAL '1' SECOND;

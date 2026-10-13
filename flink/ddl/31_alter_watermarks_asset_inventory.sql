ALTER TABLE `asset_inventory` MODIFY WATERMARK FOR `$rowtime` AS `$rowtime` - INTERVAL '1' SECOND;

CREATE TABLE `transfer_details` (
  `unique_conn_id` varchar(45) NOT NULL DEFAULT '',
  `uploader_address` varchar(45) NOT NULL DEFAULT '',
  `downloader_address` varchar(45) NOT NULL DEFAULT '',
  `date_added` datetime NOT NULL,
  PRIMARY KEY (`unique_conn_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
CREATE EVENT delete_old_connections
ON SCHEDULE EVERY 1 day
DO
    DELETE FROM transfer_details WHERE date_added < DATE_ADD(NOW(), INTERVAL -1 day);


SHOW EVENTS;
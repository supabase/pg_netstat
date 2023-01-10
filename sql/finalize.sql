CREATE VIEW pg_netstat AS
    SELECT
        device,
        to_timestamp(ts) as ts,
        packets_in,
        packets_out,
        packets_in_speed,
        packets_out_speed,
        bytes_in,
        bytes_out,
        bytes_in_speed,
        bytes_out_speed,
        to_timestamp(created_at) as created_at
    FROM
        netstat()
    ORDER BY
        device, ts
    ;

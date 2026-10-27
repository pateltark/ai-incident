-- CREATE TABLE incident_copilot.application_logs (
--     id Int64,
--     service_id Int32,
--     level LowCardinality(String),
--     message String,
--     latency_ms Nullable(Int32),
--     request_id String,
--     timestamp DateTime64(3, 'UTC')
-- ) 
-- ENGINE = MergeTree()
-- ORDER BY (service_id, level, timestamp);

-- SELECT count() FROM incident_copilot.application_logs;


SELECT timestamp, service_id, level, message 
FROM incident_copilot.application_logs 
ORDER BY timestamp DESC 
LIMIT 5;
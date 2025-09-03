-- Athena (Hive) DDL for AWS WAF logs
-- Fixed to use Hive grammar and JSON SerDe
CREATE EXTERNAL TABLE IF NOT EXISTS waf_analytics.waf_logs (
  timestamp bigint,
  formatversion int,
  webaclid string,
  terminatingruleid string,
  terminatingruletype string,
  action string,
  terminatingrulematchdetails array<struct<
    conditiontype: string,
    sensitivitylevel: string,
    location: string,
    matcheddata: array<string>
  >>,
  httpsourcename string,
  httpsourceid string,
  rulegrouplist array<struct<
    rulegroupid: string,
    terminatingrule: struct<
      ruleid: string,
      action: string,
      rulematchdetails: array<struct<
        conditiontype: string,
        sensitivitylevel: string,
        location: string,
        matcheddata: array<string>
      >>
    >,
    nonterminatingmatchingrules: array<struct<
      ruleid: string,
      action: string,
      rulematchdetails: array<struct<
        conditiontype: string,
        sensitivitylevel: string,
        location: string,
        matcheddata: array<string>
      >>
    >>,
    excludedrules: string
  >>,
  ratebasedrulelist array<struct<
    ratebasedruleid: string,
    limitkey: string,
    maxrateallowed: int
  >>,
  nonterminatingmatchingrules array<struct<
    ruleid: string,
    action: string,
    rulematchdetails: array<struct<
      conditiontype: string,
      sensitivitylevel: string,
      location: string,
      matcheddata: array<string>
    >>
  >>,
  requestheadersinserted string,
  responsecodesent string,
  httprequest struct<
    clientip: string,
    country: string,
    headers: array<struct<
      name: string,
      value: string
    >>,
    uri: string,
    args: string,
    httpversion: string,
    httpmethod: string,
    requestid: string
  >,
  labels array<struct<
    name: string
  >>
)
PARTITIONED BY (
  year string,
  month string,
  day string,
  hour string
)
ROW FORMAT SERDE 
  'org.openx.data.jsonserde.JsonSerDe'
STORED AS INPUTFORMAT 
  'org.apache.hadoop.mapred.TextInputFormat' 
OUTPUTFORMAT 
  'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://juice-shop-waf-logs-hhd1tcl4/'
TBLPROPERTIES (
  'projection.enabled'='true',
  'projection.year.type'='integer',
  'projection.year.range'='2020,2030',
  'projection.year.interval'='1',
  'projection.month.type'='integer', 
  'projection.month.range'='01,12',
  'projection.month.interval'='1',
  'projection.month.digits'='2',
  'projection.day.type'='integer',
  'projection.day.range'='01,31', 
  'projection.day.interval'='1',
  'projection.day.digits'='2',
  'projection.hour.type'='integer',
  'projection.hour.range'='00,23',
  'projection.hour.interval'='1', 
  'projection.hour.digits'='2',
  'storage.location.template'='s3://juice-shop-waf-logs-hhd1tcl4/year=${year}/month=${month}/day=${day}/hour=${hour}/',
  'serialization.format'='1'
);

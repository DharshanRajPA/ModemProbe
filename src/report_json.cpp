#include "report_json.h"

#include <json/json.h>

#include <fstream>

namespace modemprobe {

static Json::Value map_to_json_obj(const std::unordered_map<std::string, uint64_t>& m) {
  Json::Value obj(Json::objectValue);
  for (const auto& kv : m) obj[kv.first] = Json::UInt64(kv.second);
  return obj;
}

bool write_report_json(const std::string& path, const ReportData& r, std::string* err) {
  Json::Value root(Json::objectValue);
  root["protocol_counts"] = map_to_json_obj(r.protocol_counts);

  // anomalies[] as an array of summary objects, plus anomaly_counts for easy parsing.
  root["anomaly_counts"] = map_to_json_obj(r.anomaly_counts);
  Json::Value anomalies(Json::arrayValue);
  for (const auto& kv : r.anomaly_counts) {
    Json::Value a(Json::objectValue);
    a["type"] = kv.first;
    a["count"] = Json::UInt64(kv.second);
    anomalies.append(a);
  }
  root["anomalies"] = anomalies;
  root["anomaly_events_stored"] = Json::UInt64(r.anomaly_events_stored);
  root["anomaly_events_dropped"] = Json::UInt64(r.anomaly_events_dropped);

  Json::Value perf(Json::objectValue);
  perf["packets_total"] = Json::UInt64(r.packets_total);
  perf["elapsed_seconds"] = r.elapsed_seconds;
  perf["pps"] = r.pps;
  perf["avg_parse_us"] = r.avg_parse_us;
  root["performance"] = perf;

  Json::Value streams(Json::arrayValue);
  for (const auto& s : r.rtp_streams) {
    Json::Value o(Json::objectValue);
    o["ssrc"] = Json::UInt(s.ssrc);
    o["received_unique"] = Json::UInt(s.received_unique);
    o["duplicates"] = Json::UInt(s.duplicates);
    o["out_of_order"] = Json::UInt(s.out_of_order);
    o["too_old"] = Json::UInt(s.too_old);
    o["estimated_lost"] = Json::UInt(s.estimated_lost);
    o["first_ts_us"] = Json::UInt64(s.first_ts_us);
    o["last_ts_us"] = Json::UInt64(s.last_ts_us);
    o["saw_h264"] = s.saw_h264;
    streams.append(o);
  }
  root["rtp_streams"] = streams;

  Json::StreamWriterBuilder b;
  b["indentation"] = "  ";

  std::ofstream out(path, std::ios::out | std::ios::trunc);
  if (!out.is_open()) {
    if (err) *err = "failed to open output file: " + path;
    return false;
  }

  std::unique_ptr<Json::StreamWriter> w(b.newStreamWriter());
  w->write(root, &out);
  out << "\n";
  return true;
}

} // namespace modemprobe


# 15 CERT Insider Threat features — must match the host agent exactly
FEATURE_NAMES = [
    "total_logons",
    "avg_logon_hour",
    "std_logon_hour",
    "weekend_logons",
    "after_hours_logons",
    "unique_pcs_logon",
    "total_device_activities",
    "unique_pcs_device",
    "avg_device_hour",
    "after_hours_device",
    "total_file_activities",
    "unique_files",
    "unique_pcs_file",
    "avg_file_hour",
    "after_hours_files",
]

EXPECTED_FEATURE_COUNT = len(FEATURE_NAMES)
